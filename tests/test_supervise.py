"""Supervisor lifecycle: hard-kill either process, config must be cleaned.

The marker file stands in for installed DNS configuration. Each test
spawns a real supervised daemon (high ports, tmp paths: no root) and
asserts the marker is gone afterwards.
"""

import contextlib
import os
import signal
import socket
import sys
from pathlib import Path

import anyio
import pytest
from helpers import free_port

from pymacdns import installer as installer_mod
from pymacdns.control import control_request

ROOT = Path(__file__).resolve().parent.parent


def proc_env() -> dict[str, str]:
    env = dict(os.environ)
    src = str(ROOT / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    return env


def base_args(
    marker: Path, control_sock: str, port: int, resolv: Path | None = None
) -> list[str]:
    args = [
        sys.executable,
        "-m",
        "pymacdns",
        "--config",
        "/nonexistent-pymacdns.toml",
        "--marker-file",
        str(marker),
        "--listen",
        f"127.0.0.1:{port}",
        "--socket",
        control_sock,
    ]
    if resolv is not None:
        args += ["--resolv-conf", str(resolv)]
    return args


async def wait_for(path: Path, timeout: float = 10.0) -> None:
    with anyio.fail_after(timeout):
        while not path.exists():
            await anyio.sleep(0.05)


async def wait_gone(path: Path, timeout: float = 15.0) -> None:
    with anyio.fail_after(timeout):
        while path.exists():
            await anyio.sleep(0.05)


def port_free(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        return sock.connect_ex(("127.0.0.1", port)) != 0
    finally:
        sock.close()


async def spawn(
    marker: Path,
    sock_dir: Path,
    port: int,
    wait: bool = True,
    resolv: Path | None = None,
):
    control_sock = str(sock_dir / "ctl.sock")
    # Output to a file, not a pipe: nobody reads a pipe here, and a full
    # one blocks the daemon on its next write.
    with (sock_dir / "daemon.log").open("ab") as log:
        proc = await anyio.open_process(
            base_args(marker, control_sock, port, resolv),
            cwd=ROOT,
            env=proc_env(),
            stdout=log,
            stderr=log,
        )
    if wait:
        await wait_for(marker)
    return proc, control_sock


async def reap(proc) -> None:
    with contextlib.suppress(Exception):
        proc.kill()
    with contextlib.suppress(Exception):
        await proc.wait()


@pytest.mark.anyio
async def test_kill_parent_cleans_up(tmp_path, sock_dir):
    """SIGKILL the supervisor: the server must clean up and exit too."""
    marker = tmp_path / "installed"
    port = free_port()
    proc, _ = await spawn(marker, sock_dir, port)
    try:
        with anyio.fail_after(60):
            proc.kill()
            await wait_gone(marker)
            with anyio.fail_after(10):
                while not port_free(port):
                    await anyio.sleep(0.1)
            await proc.wait()
    finally:
        await reap(proc)


@pytest.mark.anyio
async def test_kill_child_cleans_up(tmp_path, sock_dir):
    """SIGKILL the server: the supervisor must clean up and exit."""
    marker = tmp_path / "installed"
    proc, control_sock = await spawn(marker, sock_dir, free_port())
    try:
        with anyio.fail_after(60):
            # The marker lands before the control socket exists; imports
            # (notably httpx) decide how far apart those two moments are.
            await wait_for(Path(control_sock))
            reply = await control_request(control_sock, {"op": "pid"})
            os.kill(reply["pid"], signal.SIGKILL)
            await proc.wait()
            await wait_gone(marker)
    finally:
        await reap(proc)


@pytest.mark.anyio
async def test_sigterm_cleans_up(tmp_path, sock_dir):
    marker = tmp_path / "installed"
    proc, _ = await spawn(marker, sock_dir, free_port())
    try:
        with anyio.fail_after(60):
            proc.terminate()
            await proc.wait()
            await wait_gone(marker)
    finally:
        await reap(proc)


def test_install_partial_rolls_back(tmp_path):
    """A failing installer leaves exactly its predecessors installed."""
    good = installer_mod.FileMarker(str(tmp_path / "good"))

    class Boom:
        def install(self) -> None:
            raise RuntimeError("boom")

        def cleanup(self) -> None:
            pass

    done: list = []
    with pytest.raises(RuntimeError, match="boom"):
        installer_mod.install_all([good, Boom()], done)
    assert done == [good]
    assert (tmp_path / "good").exists()
    installer_mod.cleanup_all(done)
    assert not (tmp_path / "good").exists()


@pytest.mark.anyio
async def test_failed_install_exits_nonzero(tmp_path, sock_dir):
    """Uninstallable config exits nonzero with nothing left behind."""
    marker = tmp_path / "no-such-dir" / "installed"
    proc, _ = await spawn(marker, sock_dir, free_port(), wait=False)
    try:
        with anyio.fail_after(60):
            code = await proc.wait()
            assert code != 0
    finally:
        await reap(proc)


@pytest.mark.anyio
async def test_resolv_conf_managed_and_restored(tmp_path, sock_dir):
    """The daemon's block is present while running, gone after exit."""
    from pymacdns.installer import BEGIN_MARK

    dummy = tmp_path / "resolv.conf"
    dummy.write_text("nameserver 9.9.9.9\n")
    before = dummy.read_bytes()
    marker = tmp_path / "installed"
    proc, _ = await spawn(marker, sock_dir, free_port(), resolv=dummy)
    try:
        with anyio.fail_after(60):
            with anyio.fail_after(10):
                while BEGIN_MARK not in dummy.read_text():
                    await anyio.sleep(0.05)
            running = dummy.read_text()
            assert "nameserver 127.0.0.1\n" in running
            assert "nameserver 9.9.9.9\n" in running
            # configd regenerates the file on DNS changes and drops the
            # block; the daemon must put it back.
            dummy.write_text("nameserver 9.9.9.9\n")
            with anyio.fail_after(10):
                while BEGIN_MARK not in dummy.read_text():
                    await anyio.sleep(0.05)
            proc.terminate()
            await proc.wait()
            assert dummy.read_bytes() == before
    finally:
        await reap(proc)


@pytest.mark.anyio
async def test_release_drops_settings_and_keeps_serving(tmp_path, sock_dir):
    """release removes what the daemon installed, and it stays removed."""
    from pymacdns.installer import BEGIN_MARK
    from pymacdns.supervise import REAPPLY_INTERVAL

    dummy = tmp_path / "resolv.conf"
    dummy.write_text("nameserver 9.9.9.9\n")
    before = dummy.read_bytes()
    marker = tmp_path / "installed"
    proc, control_sock = await spawn(marker, sock_dir, free_port(), resolv=dummy)
    try:
        with anyio.fail_after(60):
            await wait_for(Path(control_sock))
            pid = (await control_request(control_sock, {"op": "pid"}))["pid"]
            reply = await control_request(control_sock, {"op": "release"})
            assert reply == {"released": True}
            assert not marker.exists()
            assert dummy.read_bytes() == before
            # Past a reapply tick: nothing may come back.
            await anyio.sleep(REAPPLY_INTERVAL * 2)
            assert BEGIN_MARK not in dummy.read_text()
            assert not marker.exists()
            assert proc.returncode is None
            reply = await control_request(control_sock, {"op": "pid"})
            assert reply == {"pid": pid}
    finally:
        await reap(proc)
