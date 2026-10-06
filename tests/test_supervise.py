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

from pymacdns.control import control_request

ROOT = Path(__file__).resolve().parent.parent


def proc_env() -> dict[str, str]:
    env = dict(os.environ)
    src = str(ROOT / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    return env


def base_args(marker: Path, control_sock: str, port: int) -> list[str]:
    return [
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
        "--no-resolv-conf",
    ]


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


async def spawn(marker: Path, tag: str, port: int):
    control_sock = f"/tmp/pmdns-{os.getpid()}-{tag}.sock"
    proc = await anyio.open_process(
        base_args(marker, control_sock, port), cwd=ROOT, env=proc_env()
    )
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
