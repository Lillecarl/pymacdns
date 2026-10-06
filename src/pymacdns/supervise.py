from __future__ import annotations

import os
import signal
import socket
from collections.abc import Awaitable, Callable

import anyio

from pymacdns import installer as installer_mod


def run_supervised(
    installers: list[installer_mod.Installer],
    child_main: Callable[[], Awaitable[None]],
) -> int:
    """Fork early into supervisor and server, return the exit code.

    Must be called before any thread or event loop exists: fork only
    preserves the calling thread. The fork comes first so partial
    installation always has an owner: the child installs with tracked
    rollback, and the parent cleans the full list as a backstop when
    the child dies at any point, including mid-install or by SIGKILL.
    The child watches the pipe (EOF means the parent died) and shuts
    itself down. Cleanup is idempotent so double-clean is safe.
    """
    parent_end, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    parent_end.set_inheritable(True)
    child_end.set_inheritable(True)
    pid = os.fork()
    if pid > 0:
        child_end.close()
        return _supervise(pid, parent_end.fileno(), installers)
    parent_end.close()
    fd = child_end.fileno()
    child_end.detach()
    return anyio.run(_child, fd, installers, child_main)


def _supervise(
    child_pid: int, pipe_fd: int, installers: list[installer_mod.Installer]
) -> int:
    stop = False

    def on_signal(signum: int, frame: object) -> None:
        nonlocal stop
        stop = True
        try:
            os.kill(child_pid, signal.SIGTERM)
        except OSError:
            pass

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    try:
        _, status = os.waitpid(child_pid, 0)
    except ChildProcessError:
        status = 0
    installer_mod.cleanup_all(installers)
    try:
        os.close(pipe_fd)
    except OSError:
        pass
    if stop:
        return 128 + signal.SIGTERM
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return 1


async def _child(
    pipe_fd: int,
    installers: list[installer_mod.Installer],
    child_main: Callable[[], Awaitable[None]],
) -> None:
    installed: list[installer_mod.Installer] = []
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(watch_parent, pipe_fd, tg.cancel_scope)
            tg.start_soon(_watch_signals, tg.cancel_scope)
            await anyio.to_thread.run_sync(
                installer_mod.install_all, installers, installed
            )
            tg.start_soon(child_main)
    finally:
        installer_mod.cleanup_all(installed)
        try:
            os.close(pipe_fd)
        except OSError:
            pass


async def watch_parent(pipe_fd: int, scope: anyio.CancelScope) -> None:
    """Cancel the server when the supervisor's pipe end closes."""

    def _read() -> bytes:
        try:
            return os.read(pipe_fd, 1)
        except OSError:
            return b""

    while True:
        chunk = await anyio.to_thread.run_sync(_read, abandon_on_cancel=True)
        if not chunk:
            scope.cancel()
            return


async def _watch_signals(scope: anyio.CancelScope) -> None:
    with anyio.open_signal_receiver(signal.SIGTERM, signal.SIGINT) as signals:
        async for _ in signals:
            scope.cancel()
            return
