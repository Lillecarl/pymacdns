from __future__ import annotations

import queue
import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import anyio

from pymacdns import resolver as resolver_mod
from pymacdns.config import DEFAULT_LISTEN, normalize_domain

GLOBAL_DNS_KEY: Final = "State:/Network/Global/DNS"
SERVICE_DNS_PATTERN: Final = r"State:/Network/Service/.*/DNS"
SERVICE_NOTIFY_PATTERNS: Final = [
    r"State:/Network/Service/.*",
    r"Setup:/Network/Service/.*",
]
RESOLVER_DIR: Final = "/etc/resolver"
RUNLOOP_TICK: Final = 1.0

# Source precedence for same-domain conflicts: lower rank wins.
TOML_RANK: Final = 0
FILE_RANK: Final = 1
STORE_RANK: Final = 2
# Priorities observed in scutil --dns: the default resolver shows none
# (implicit first), supplemental VPN resolvers carry explicit orders
# such as 100600/103000, mDNS sits at 300000+. VPN clients that set no
# order (e.g. ZeroTier's MacDNSHelper) land here.
SUPPLEMENTAL_DEFAULT_PRIORITY: Final = 100000
# /etc/resolver/<domain> entries show no order in scutil --dns and
# behave as domain-scoped entries, so they join the 100000 class.
FILE_PRIORITY: Final = 100000
# The system default sorts after VPN supplemental entries: Apple
# documents that an empty SupplementalMatchDomains entry directs all
# queries to the VPN DNS *first*, and observed primary-service orders
# sit around 200000.
GLOBAL_DEFAULT_PRIORITY: Final = 200000


@dataclass(frozen=True)
class Candidate:
    domain: str  # "" is the catch-all
    nameservers: tuple[str, ...]
    priority: int
    source_rank: int


@dataclass(frozen=True)
class ServiceDns:
    """One State:/Network/Service/*/DNS dictionary in plain types.

    Shapes follow Apple's DNS dictionary (ServerAddresses,
    SupplementalMatchDomains, SupplementalMatchOrders) as written by
    real VPN clients such as ZeroTier's MacDNSHelper and NetBird's
    host_darwin configurator.
    """

    servers: tuple[str, ...] = ()
    match_domains: tuple[str, ...] = ()
    match_orders: tuple[str, ...] = ()


@dataclass
class Snapshot:
    standard: resolver_mod.Upstream | None = None
    domains: dict[str, resolver_mod.Upstream] = field(default_factory=dict)


def _str_list(value: object) -> list[str]:
    if value is None:
        return []
    return [str(item) for item in list(value)]  # type: ignore[arg-type]


def merge_to_snapshot(candidates: list[Candidate], timeout: float) -> Snapshot:
    """Merge one winner list per domain.

    Same-domain candidates concatenate nameservers in priority order
    (then source rank), so a VPN supplemental entry with an empty
    domain means "ask VPN DNS first, fall back to the default" exactly
    as Apple documents. lookup() already tries them in order.
    """
    grouped: dict[str, list[Candidate]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.domain, []).append(candidate)

    def servers(group: list[Candidate]) -> list[str]:
        ordered = sorted(group, key=lambda c: (c.priority, c.source_rank))
        seen: list[str] = []
        for candidate in ordered:
            for nameserver in candidate.nameservers:
                if nameserver not in seen:
                    seen.append(nameserver)
        return seen

    standard_addrs = servers(grouped.pop("", []))
    return Snapshot(
        standard=resolver_mod.Upstream(nameservers=standard_addrs, timeout=timeout)
        if standard_addrs
        else None,
        domains={
            domain: resolver_mod.Upstream(nameservers=servers(group), timeout=timeout)
            for domain, group in grouped.items()
            if servers(group)
        },
    )


def system_candidates(
    global_addrs: list[str],
    services: list[ServiceDns],
    self_hosts: set[str],
) -> list[Candidate]:
    """Build candidates from plain store data. Pure function for tests."""
    found = [
        Candidate(
            domain="",
            nameservers=tuple(
                addr for addr in global_addrs if addr not in self_hosts
            ),
            priority=GLOBAL_DEFAULT_PRIORITY,
            source_rank=STORE_RANK,
        )
    ]
    for service in services:
        addrs = tuple(addr for addr in service.servers if addr not in self_hosts)
        if not addrs:
            continue
        for index, domain in enumerate(service.match_domains):
            try:
                priority = (
                    int(service.match_orders[index])
                    if index < len(service.match_orders)
                    else SUPPLEMENTAL_DEFAULT_PRIORITY
                )
            except ValueError:
                priority = SUPPLEMENTAL_DEFAULT_PRIORITY
            found.append(
                Candidate(
                    domain=normalize_domain(domain),
                    nameservers=addrs,
                    priority=priority,
                    source_rank=STORE_RANK,
                )
            )
    return [c for c in found if c.nameservers or c.domain]


def file_candidates(
    files: dict[str, str], self_hosts: set[str]
) -> list[Candidate]:
    """Build candidates from /etc/resolver/<domain> file contents. Pure."""
    found = []
    for domain, text in sorted(files.items()):
        if domain.startswith("."):
            continue
        addrs = tuple(
            parts[1]
            for line in text.splitlines()
            if len(parts := line.split()) >= 2
            and parts[0] == "nameserver"
            and parts[1] not in self_hosts
        )
        if addrs:
            found.append(
                Candidate(
                    domain=normalize_domain(domain),
                    nameservers=addrs,
                    priority=FILE_PRIORITY,
                    source_rank=FILE_RANK,
                )
            )
    return found


def _fetch_store_dicts() -> tuple[list[str], list[ServiceDns]]:
    """Read Global + per-service DNS dicts, converted to plain types."""
    from SystemConfiguration import (
        SCDynamicStoreCopyKeyList,
        SCDynamicStoreCopyValue,
        SCDynamicStoreCreate,
    )

    store = SCDynamicStoreCreate(None, "pymacdns", None, None)
    global_info = dict(SCDynamicStoreCopyValue(store, GLOBAL_DNS_KEY) or {})
    services = []
    for key in SCDynamicStoreCopyKeyList(store, SERVICE_DNS_PATTERN) or []:
        info = dict(SCDynamicStoreCopyValue(store, str(key)) or {})
        services.append(
            ServiceDns(
                servers=tuple(_str_list(info.get("ServerAddresses"))),
                match_domains=tuple(_str_list(info.get("SupplementalMatchDomains"))),
                match_orders=tuple(_str_list(info.get("SupplementalMatchOrders"))),
            )
        )
    return _str_list(global_info.get("ServerAddresses")), services


def _read_system(self_hosts: set[str]) -> list[Candidate]:
    """Default + supplemental resolvers from the dynamic store."""
    global_addrs, services = _fetch_store_dicts()
    return system_candidates(global_addrs, services, self_hosts)


def _read_files(
    self_hosts: set[str], resolver_dir: str = RESOLVER_DIR
) -> list[Candidate]:
    """Domain-scoped resolvers from /etc/resolver/<domain> files."""
    directory = Path(resolver_dir)
    files = {}
    if directory.is_dir():
        for entry in sorted(directory.iterdir()):
            if entry.name.startswith(".") or not entry.is_file():
                continue
            try:
                files[entry.name] = entry.read_text()
            except OSError:
                continue
    return file_candidates(files, self_hosts)


def _run_watcher(
    out: queue.Queue[Snapshot | None],
    timeout: float,
    self_hosts: set[str],
    config_path: str,
    stop: threading.Event,
) -> None:
    from CoreFoundation import (
        CFRunLoopAddSource,
        CFRunLoopGetCurrent,
        CFRunLoopRunInMode,
        kCFRunLoopDefaultMode,
    )
    from SystemConfiguration import (
        SCDynamicStoreCreate,
        SCDynamicStoreCreateRunLoopSource,
        SCDynamicStoreSetNotificationKeys,
    )

    from pymacdns.config import load_config

    store = SCDynamicStoreCreate(None, "pymacdns-watch", lambda *args: None, None)
    SCDynamicStoreSetNotificationKeys(store, [GLOBAL_DNS_KEY], SERVICE_NOTIFY_PATTERNS)
    source = SCDynamicStoreCreateRunLoopSource(None, store, 0)
    loop = CFRunLoopGetCurrent()
    CFRunLoopAddSource(loop, source, kCFRunLoopDefaultMode)

    last: Snapshot | None = None
    toml_mtime: int | None = None
    toml_rules: list[Candidate] = []
    target = Path(config_path)
    while not stop.is_set():
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, RUNLOOP_TICK, False)
        if stop.is_set():
            break
        try:
            system = _read_system(self_hosts)
            files = _read_files(self_hosts)
        except Exception:  # noqa: BLE001 - keep watching, next tick retries
            continue
        try:
            mtime = target.stat().st_mtime_ns if target.is_file() else None
        except OSError:
            mtime = None
        if mtime != toml_mtime:
            try:
                config = load_config(target)
                toml_rules = [
                    Candidate(
                        domain=rule.domain,
                        nameservers=rule.nameservers,
                        priority=rule.priority,
                        source_rank=TOML_RANK,
                    )
                    for rule in config.resolvers
                ]
                toml_mtime = mtime
            except ValueError:  # noqa: BLE001 - keep last-good config
                pass
        snap = merge_to_snapshot(system + files + toml_rules, timeout)
        if snap != last:
            last = snap
            out.put(snap)


async def watch(
    timeout: float, self_hosts: set[str], config_path: str
) -> AsyncIterator[Snapshot]:
    """Yield the current DNS snapshot, then a new one on every change."""
    out: queue.Queue[Snapshot | None] = queue.Queue()
    stop = threading.Event()
    thread = threading.Thread(
        target=_run_watcher,
        args=(out, timeout, self_hosts, config_path, stop),
        daemon=True,
    )
    thread.start()
    try:
        while True:
            # abandon_on_cancel: the worker blocks in get() with no timeout,
            # so a cancelled receive must not wait for it. The finally below
            # puts a sentinel that wakes the abandoned worker; its result is
            # discarded and the thread exits.
            snap = await anyio.to_thread.run_sync(out.get, abandon_on_cancel=True)
            if snap is None:
                return
            yield snap
    finally:
        stop.set()
        out.put(None)
        await anyio.to_thread.run_sync(thread.join, RUNLOOP_TICK + 2.0)


DUMP_SELF_HOSTS: Final = frozenset({"127.0.0.1", "::1"})


def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def dump_toml(self_hosts: set[str] | frozenset[str] = DUMP_SELF_HOSTS) -> str:
    """Render live macOS resolver state as TOML in FileConfig schema.

    Synchronous one-shot for the dump subcommand. Self addresses are
    left out so redirecting the output into a config file cannot
    create a forward loop once pymacdns serves system DNS.
    """
    hosts = set(self_hosts)
    lines = [
        "# Generated by `pymacdns dump` from live macOS resolver state.",
        "# Paste entries into your config file and adjust priorities.",
        "# Longest domain match routes; ties go to the lowest priority,",
        "# then TOML over /etc/resolver over system. Negative priorities",
        "# outrank the system default (0).",
        '# pymacdns forwards whatever query types it receives; if macOS',
        '# only issues A queries, AAAA answers never happen. That call is',
        "# the system's, not the forwarder's.",
        '[server]',
        f"listen = [{', '.join(_toml_str(entry) for entry in DEFAULT_LISTEN)}]",
        "timeout = 2.0",
        "interval = 1.0",
    ]
    for candidate in _read_system(hosts):
        if candidate.domain:
            lines.append(
                f"# Supplemental resolver from State:/Network/Service/*/DNS, "
                f"system order {candidate.priority}."
            )
        else:
            lines.append("# System default resolver (State:/Network/Global/DNS).")
        lines.extend(_rule_toml(candidate))
    for candidate in _read_files(hosts):
        lines.append(f"# From /etc/resolver/{candidate.domain}.")
        lines.extend(_rule_toml(candidate))
    return "\n".join(lines) + "\n"


def _rule_toml(candidate: Candidate) -> list[str]:
    servers = ", ".join(_toml_str(ns) for ns in candidate.nameservers)
    lines = ["[[resolver]]"]
    if candidate.domain:
        lines.append(f"domain = {_toml_str(candidate.domain)}")
    lines.append(f"nameservers = [{servers}]")
    lines.append(f"priority = {candidate.priority}")
    return lines
