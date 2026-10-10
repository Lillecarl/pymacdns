from __future__ import annotations

import os
import signal
import socket
import sys
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Final

import anyio

from pymacdns import installer as installer_mod

if TYPE_CHECKING:
    from pymacdns.control import Lifecycle

REAPPLY_INTERVAL: Final = 2.0


def run_supervised(
    installers: list[installer_mod.Installer],
    child_main: Callable[[Lifecycle], Awaitable[None]],
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
    child_main: Callable[[Lifecycle], Awaitable[None]],
) -> None:
    installation = Installation(installers)
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(watch_parent, pipe_fd, tg.cancel_scope)
            tg.start_soon(_watch_signals, tg.cancel_scope)
            await anyio.to_thread.run_sync(
                installer_mod.install_all, installers, installation.installed
            )
            tg.start_soon(installation.reapply_forever)
            tg.start_soon(child_main, installation)
    finally:
        installer_mod.cleanup_all(installation.installed)
        try:
            os.close(pipe_fd)
        except OSError:
            pass


class Installation:
    """The settings the server installed, and the control socket's hold on them.

    One lock serialises reapply, release and restore, so a reapply in
    flight cannot rewrite what a release has just removed.
    """

    def __init__(self, installers: list[installer_mod.Installer]) -> None:
        self.installers = installers
        self.installed: list[installer_mod.Installer] = []
        self.released = False
        self._lock = anyio.Lock()

    async def release(self) -> None:
        async with self._lock:
            self.released = True
            await anyio.to_thread.run_sync(
                installer_mod.cleanup_all, self.installed
            )
            self.installed.clear()

    async def restore(self) -> None:
        async with self._lock:
            if not self.released:
                return
            try:
                await anyio.to_thread.run_sync(
                    installer_mod.install_all, self.installers, self.installed
                )
            except BaseException:
                await anyio.to_thread.run_sync(
                    installer_mod.cleanup_all, self.installed
                )
                self.installed.clear()
                raise
            self.released = False

    async def reapply_forever(self) -> None:
        while True:
            await anyio.sleep(REAPPLY_INTERVAL)
            async with self._lock:
                if self.released:
                    continue
                try:
                    await anyio.to_thread.run_sync(
                        installer_mod.reapply_all, self.installed
                    )
                except Exception as exc:  # noqa: BLE001 - keep serving, retry
                    print(f"pymacdns: reapply failed: {exc}", file=sys.stderr)


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
