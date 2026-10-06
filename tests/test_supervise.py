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
    marker: Path, tag: str, port: int, wait: bool = True, resolv: Path | None = None
):
    control_sock = f"/tmp/pmdns-{os.getpid()}-{tag}.sock"
    proc = await anyio.open_process(
        base_args(marker, control_sock, port, resolv), cwd=ROOT, env=proc_env()
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
async def test_kill_parent_cleans_up(tmp_path):
    """SIGKILL the supervisor: the server must clean up and exit too."""
    marker = tmp_path / "installed"
    proc, _ = await spawn(marker, "kp", 15521)
    try:
        with anyio.fail_after(60):
            proc.kill()
            await wait_gone(marker)
            with anyio.fail_after(10):
                while not port_free(15521):
                    await anyio.sleep(0.1)
            await proc.wait()
    finally:
        await reap(proc)


@pytest.mark.anyio
async def test_kill_child_cleans_up(tmp_path):
    """SIGKILL the server: the supervisor must clean up and exit."""
    marker = tmp_path / "installed"
    proc, control_sock = await spawn(marker, "kc", 15522)
    try:
        with anyio.fail_after(60):
            reply = await control_request(control_sock, {"op": "pid"})
            os.kill(reply["pid"], signal.SIGKILL)
            await proc.wait()
            await wait_gone(marker)
    finally:
        await reap(proc)


@pytest.mark.anyio
async def test_sigterm_cleans_up(tmp_path):
    marker = tmp_path / "installed"
    proc, _ = await spawn(marker, "st", 15523)
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
async def test_failed_install_exits_nonzero(tmp_path):
    """Uninstallable config exits nonzero with nothing left behind."""
    marker = tmp_path / "no-such-dir" / "installed"
    proc, _ = await spawn(marker, "fi", 15524, wait=False)
    try:
        with anyio.fail_after(60):
            code = await proc.wait()
            assert code != 0
    finally:
        await reap(proc)


@pytest.mark.anyio
async def test_resolv_conf_managed_and_restored(tmp_path):
    """The daemon's block is present while running, gone after exit."""
    from pymacdns.installer import BEGIN_MARK

    dummy = tmp_path / "resolv.conf"
    dummy.write_text("nameserver 9.9.9.9\n")
    before = dummy.read_bytes()
    marker = tmp_path / "installed"
    proc, _ = await spawn(marker, "rc", 15525, resolv=dummy)
    try:
        with anyio.fail_after(60):
            with anyio.fail_after(10):
                while BEGIN_MARK not in dummy.read_text():
                    await anyio.sleep(0.05)
            running = dummy.read_text()
            assert "nameserver 127.0.0.1\n" in running
            assert "nameserver 9.9.9.9\n" in running
            proc.terminate()
            await proc.wait()
            assert dummy.read_bytes() == before
    finally:
        await reap(proc)
