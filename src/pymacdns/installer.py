from __future__ import annotations

import contextlib
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol


class Installer(Protocol):
    """Something installed while the daemon runs, removed on exit.

    Both supervisor and server call cleanup; every implementation
    must be idempotent.
    """

    def install(self) -> None: ...
    def cleanup(self) -> None: ...


@dataclass
class FileMarker:
    """Stand-in installer that maintains a file while running.

    Used to prove the supervision lifecycle; real DNS installers
    slot into the same list alongside ResolvConf below.
    """

    path: str

    def install(self) -> None:
        with open(self.path, "w") as handle:
            handle.write("pymacdns\n")

    def cleanup(self) -> None:
        try:
            os.unlink(self.path)
        except OSError:
            pass


def install_all(items: list[Installer], done: list[Installer]) -> None:
    """Install in order, appending successes to done.

    Raises on first failure, leaving exactly the installed subset in
    done so the caller can roll back partial success. Cleanup of
    never-installed items must still be safe: the supervisor cleans
    the full list as a backstop.
    """
    for item in items:
        item.install()
        done.append(item)


def cleanup_all(items: list[Installer]) -> None:
    for item in items:
        try:
            item.cleanup()
        except Exception as exc:  # noqa: BLE001 - best effort, keep going
            print(f"pymacdns: cleanup failed: {exc}", file=sys.stderr)


BEGIN_MARK: Final = "# BEGIN pymacdns (managed - do not edit)"
END_MARK: Final = "# END pymacdns"


def _block_span(text: str) -> tuple[int, int] | None:
    """Locate our block as (first line, one-past-END line), or None.

    Only a complete BEGIN..END pair counts: a lone BEGIN is not ours,
    so cleanup never touches half-written or hand-edited fragments.
    """
    lines = text.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == BEGIN_MARK), None
    )
    if start is None:
        return None
    end = next(
        (
            i
            for i, line in enumerate(lines)
            if i > start and line.strip() == END_MARK
        ),
        None,
    )
    if end is None:
        return None
    return start, end + 1


def _atomic_write(path: str, text: str) -> None:
    """Write via temp file + rename; preserve the existing mode, if any."""
    target = Path(path)
    try:
        mode = stat.S_IMODE(target.stat().st_mode)
    except FileNotFoundError:
        mode = None
    fd, tmp = tempfile.mkstemp(
        dir=str(target.parent), prefix=".pymacdns-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@dataclass
class ResolvConf:
    """Point a resolv.conf at our listeners through a delimited block.

    install() prepends the block, or refreshes it in place when a
    previous run left one. cleanup() removes exactly that block and
    restores the rest byte-for-byte, unlinking the file when nothing
    but blank lines remain (an empty resolv.conf resolves nothing,
    same as a missing one). Without a complete pair neither touches
    the file; install() raises on a lone BEGIN instead of guessing
    what is ours. Stateless by design: the supervisor's backstop
    cleanup runs on an object that never saw install().
    """

    path: str
    nameservers: list[str]

    def _target(self) -> str:
        # Through the link, never instead of it: /etc/resolv.conf is a
        # symlink to /private/var/run/resolv.conf, and os.replace on the
        # link path would swap the link itself for a regular file.
        return os.path.realpath(self.path)

    def block(self) -> str:
        lines = [
            BEGIN_MARK,
            *(f"nameserver {ns}" for ns in self.nameservers),
            END_MARK,
        ]
        return "\n".join(lines) + "\n"

    def install(self) -> None:
        target = self._target()
        try:
            original = Path(target).read_text(encoding="utf-8")
        except FileNotFoundError:
            original = ""
        span = _block_span(original)
        if span is None and any(
            line.strip() == BEGIN_MARK for line in original.splitlines()
        ):
            raise ValueError(f"{self.path}: found BEGIN without END, refusing")
        if span is None:
            updated = self.block() + original
        else:
            start, end = span
            lines = original.splitlines(keepends=True)
            updated = "".join(lines[:start]) + self.block() + "".join(lines[end:])
        if updated != original:
            _atomic_write(target, updated)

    def cleanup(self) -> None:
        target = self._target()
        try:
            original = Path(target).read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        span = _block_span(original)
        if span is None:
            return
        start, end = span
        lines = original.splitlines(keepends=True)
        rest = "".join(lines[:start] + lines[end:])
        if rest.strip() == "":
            with contextlib.suppress(FileNotFoundError):
                os.unlink(target)
        else:
            _atomic_write(target, rest)
