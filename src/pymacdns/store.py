from __future__ import annotations

import queue
import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import anyio

from pymacdns import resolver as resolver_mod
from pymacdns.config import normalize_domain

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
# Priorities observed in scutil --dns: default has none (0),
# supplemental VPN resolvers carry explicit orders (100000+),
# mDNS sits at 300000+. /etc/resolver entries show no order and
# behave as domain-scoped entries, so they join the 100000 class.
FILE_PRIORITY: Final = 100000
SUPPLEMENTAL_DEFAULT_PRIORITY: Final = 100000


@dataclass(frozen=True)
class Candidate:
    domain: str  # "" is the catch-all
    nameservers: tuple[str, ...]
    priority: int
    source_rank: int


@dataclass
class Snapshot:
    standard: resolver_mod.Upstream | None = None
    domains: dict[str, resolver_mod.Upstream] = field(default_factory=dict)


def _str_list(value: object) -> list[str]:
    if value is None:
        return []
    return [str(item) for item in list(value)]  # type: ignore[arg-type]


def merge_to_snapshot(candidates: list[Candidate], timeout: float) -> Snapshot:
    """Pick one winner per domain: lowest priority, then lowest source rank."""
    best: dict[str, Candidate] = {}
    for candidate in candidates:
        prev = best.get(candidate.domain)
        if prev is None or (candidate.priority, candidate.source_rank) < (
            prev.priority,
            prev.source_rank,
        ):
            best[candidate.domain] = candidate
    standard = best.pop("", None)
    return Snapshot(
        standard=resolver_mod.Upstream(
            nameservers=list(standard.nameservers), timeout=timeout
        )
        if standard is not None
        else None,
        domains={
            domain: resolver_mod.Upstream(
                nameservers=list(winner.nameservers), timeout=timeout
            )
            for domain, winner in best.items()
        },
    )


def _read_system(self_hosts: set[str]) -> list[Candidate]:
    """Default + supplemental resolvers from the dynamic store."""
    from SystemConfiguration import (
        SCDynamicStoreCopyKeyList,
        SCDynamicStoreCopyValue,
        SCDynamicStoreCreate,
    )

    store = SCDynamicStoreCreate(None, "pymacdns", None, None)
    found: list[Candidate] = []

    global_info = dict(SCDynamicStoreCopyValue(store, GLOBAL_DNS_KEY) or {})
    addrs = tuple(
        addr
        for addr in _str_list(global_info.get("ServerAddresses"))
        if addr not in self_hosts
    )
    if addrs:
        found.append(
            Candidate(domain="", nameservers=addrs, priority=0, source_rank=STORE_RANK)
        )

    for key in SCDynamicStoreCopyKeyList(store, SERVICE_DNS_PATTERN) or []:
        info = dict(SCDynamicStoreCopyValue(store, str(key)) or {})
        addrs = tuple(
            addr
            for addr in _str_list(info.get("ServerAddresses"))
            if addr not in self_hosts
        )
        if not addrs:
            continue
        orders = _str_list(info.get("SupplementalMatchOrders"))
        for index, domain in enumerate(_str_list(info.get("SupplementalMatchDomains"))):
            if index < len(orders):
                try:
                    priority = int(orders[index])
                except ValueError:
                    priority = SUPPLEMENTAL_DEFAULT_PRIORITY
            else:
                priority = SUPPLEMENTAL_DEFAULT_PRIORITY
            found.append(
                Candidate(
                    domain=normalize_domain(domain),
                    nameservers=addrs,
                    priority=priority,
                    source_rank=STORE_RANK,
                )
            )
    return found


def _read_files(self_hosts: set[str]) -> list[Candidate]:
    """Domain-scoped resolvers from /etc/resolver/<domain> files."""
    found: list[Candidate] = []
    resolver_dir = Path(RESOLVER_DIR)
    if not resolver_dir.is_dir():
        return found
    for entry in sorted(resolver_dir.iterdir()):
        if entry.name.startswith(".") or not entry.is_file():
            continue
        try:
            text = entry.read_text()
        except OSError:
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
                    domain=normalize_domain(entry.name),
                    nameservers=addrs,
                    priority=FILE_PRIORITY,
                    source_rank=FILE_RANK,
                )
            )
    return found


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
        '[global]',
        'listen = "127.0.0.1:53"',
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
