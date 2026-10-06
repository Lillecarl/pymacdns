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
    preserves the calling thread. The parent installs, forks, then
    reaps the child with waitpid (which fires on any death including
    SIGKILL). The child serves and watches the pipe: EOF means the
    parent died. Whoever survives a death cleans up; cleanup is
    idempotent so double-clean is safe.
    """
    parent_end, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    parent_end.set_inheritable(True)
    child_end.set_inheritable(True)
    installer_mod.install_all(installers)
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
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(child_main)
            tg.start_soon(watch_parent, pipe_fd, tg.cancel_scope)
            tg.start_soon(_watch_signals, tg.cancel_scope)
    finally:
        installer_mod.cleanup_all(installers)
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
