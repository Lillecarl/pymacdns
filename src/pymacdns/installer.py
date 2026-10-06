from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Protocol


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
    (resolv.conf restore, system DNS) slot into the same list later.
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


def install_all(items: list[Installer]) -> None:
    for item in items:
        item.install()


def cleanup_all(items: list[Installer]) -> None:
    for item in items:
        try:
            item.cleanup()
        except Exception as exc:  # noqa: BLE001 - best effort, keep going
            print(f"pymacdns: cleanup failed: {exc}", file=sys.stderr)
