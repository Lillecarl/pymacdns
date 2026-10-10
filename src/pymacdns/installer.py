from __future__ import annotations

import contextlib
import os
import stat
import sys
import tempfile
from dataclasses import dataclass, field
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


SYSTEM_DNS_KEY: Final = "State:/Network/Service/pymacdns/DNS"
# Lowest order wins. VPN clients use 100000 and up, the primary service
# about 200000 and mDNS 300000, so 1 puts us first. "local" and the mDNS
# reverse zones still win for their names: mDNSResponder takes the
# longest matching domain before it looks at the order.
SYSTEM_DNS_ORDER: Final = 1
DNS_PORT: Final = 53


def system_dns_dict(listen: list[tuple[str, int]]) -> dict[str, object]:
    """The SCDynamicStore DNS dictionary that routes every name to listen."""
    ports = {port for _, port in listen}
    if len(ports) != 1:
        raise ValueError(f"system DNS needs one listen port, got {sorted(ports)}")
    value: dict[str, object] = {
        "ServerAddresses": [host for host, _ in listen],
        "SupplementalMatchDomains": [""],
        "SupplementalMatchOrders": [SYSTEM_DNS_ORDER],
    }
    (port,) = ports
    if port != DNS_PORT:
        value["ServerPort"] = port
    return value


@dataclass
class SystemDns:
    """Publish our listeners to mDNSResponder through SCDynamicStore.

    The value is temporary: configd drops it when the session that added
    it closes, so a SIGKILLed daemon leaves no stale resolver behind.
    The session must therefore live as long as the daemon. Discovery in
    store.py skips our own addresses, so this entry never loops back.
    """

    listen: list[tuple[str, int]]
    _session: object | None = field(default=None, init=False, repr=False)

    def install(self) -> None:
        from SystemConfiguration import (
            SCDynamicStoreAddTemporaryValue,
            SCDynamicStoreCreate,
            SCDynamicStoreRemoveValue,
            SCError,
            SCErrorString,
        )

        value = system_dns_dict(self.listen)
        if self._session is None:
            self._session = SCDynamicStoreCreate(None, "pymacdns-dns", None, None)
        # AddTemporaryValue refuses an existing key.
        SCDynamicStoreRemoveValue(self._session, SYSTEM_DNS_KEY)
        if not SCDynamicStoreAddTemporaryValue(self._session, SYSTEM_DNS_KEY, value):
            raise RuntimeError(
                f"cannot publish {SYSTEM_DNS_KEY}: {SCErrorString(SCError())}"
            )

    def cleanup(self) -> None:
        from SystemConfiguration import SCDynamicStoreCreate, SCDynamicStoreRemoveValue

        session = self._session or SCDynamicStoreCreate(
            None, "pymacdns-dns", None, None
        )
        SCDynamicStoreRemoveValue(session, SYSTEM_DNS_KEY)
        self._session = None


SYSTEM_RESOLV_CONF: Final = "/etc/resolv.conf"


def nuke_targets(configured: list[Installer]) -> list[Installer]:
    """Configured installers plus the system ones, each once.

    The system ones join even when the config leaves them out: an
    older config, or a config that failed to load, may have
    installed them.
    """
    targets: list[Installer] = []
    seen: set[tuple[type, str]] = set()
    for item in [
        *configured,
        SystemDns(listen=[]),
        ResolvConf(path=SYSTEM_RESOLV_CONF, nameservers=[]),
    ]:
        key = (type(item), os.path.realpath(getattr(item, "path", "")))
        if key not in seen:
            seen.add(key)
            targets.append(item)
    return targets
