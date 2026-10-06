from __future__ import annotations

from dataclasses import dataclass, field

import anyio


@dataclass
class ResolverInfo:
    search_domains: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    domain: str = ""
    reachable: bool = False
    timeout: int = 0
    is_mdns: bool = False


@dataclass
class DnsConfig:
    resolvers: list[ResolverInfo] = field(default_factory=list)


@dataclass
class DnsInfo:
    config: DnsConfig = field(default_factory=DnsConfig)
    scoped: DnsConfig = field(default_factory=DnsConfig)


def parse_scutil_dns(data: str) -> DnsInfo:
    """Parse `scutil --dns` output into structured resolvers.

    Pure function with no IO, ported from dns-heaven's osx/scutil.go.
    """
    info = DnsInfo()
    current: DnsConfig | None = None
    current_resolver: ResolverInfo | None = None

    for line in data.splitlines():
        if line == "DNS configuration":
            current = info.config
            continue
        if line == "DNS configuration (for scoped queries)":
            current = info.scoped
            continue
        if line.startswith("resolver #"):
            if current is None:
                continue
            current_resolver = ResolverInfo()
            current.resolvers.append(current_resolver)
        elif line.startswith("  ") or line.startswith("\t"):
            if current_resolver is None:
                continue
            name, sep, value = line.partition(":")
            if not sep:
                continue
            name = name.strip()
            value = value.strip()
            if name.startswith("search domain"):
                current_resolver.search_domains.append(value)
            elif name.startswith("nameserver"):
                current_resolver.nameservers.append(value)
            elif name == "reach":
                current_resolver.reachable = "Not Reachable" not in value
            elif name == "domain":
                current_resolver.domain = value
            elif name == "timeout":
                try:
                    current_resolver.timeout = int(value)
                except ValueError:
                    continue
            elif name == "options":
                current_resolver.is_mdns = "mdns" in value

    return info


def _is_self(nameservers: list[str], self_hosts: set[str]) -> bool:
    if not nameservers:
        return True
    return all(ns in self_hosts for ns in nameservers)


def select_upstreams(
    info: DnsInfo,
    self_hosts: set[str],
) -> tuple[ResolverInfo | None, dict[str, ResolverInfo]]:
    """Pick the default resolver and per-domain resolvers.

    Skips unreachable, mDNS, empty, and self-referential entries so that
    pointing system DNS at ourselves does not create a forward loop.
    """
    standard: ResolverInfo | None = None
    domains: dict[str, ResolverInfo] = {}

    for resolver in info.config.resolvers:
        if not resolver.reachable:
            continue
        if resolver.is_mdns:
            continue
        if not resolver.nameservers:
            continue
        if _is_self(resolver.nameservers, self_hosts):
            continue
        if not resolver.domain:
            if standard is None:
                standard = resolver
        else:
            domains.setdefault(resolver.domain, resolver)

    return standard, domains


def resolver_for_qname(
    qname: str,
    domains: dict[str, ResolverInfo],
    standard: ResolverInfo | None,
) -> ResolverInfo | None:
    """Longest-suffix match of qname against split-DNS domains."""
    needle = qname.lower()
    if not needle.endswith("."):
        needle += "."
    best: ResolverInfo | None = None
    best_len = -1
    for domain, resolver in domains.items():
        suffix = domain.lower().rstrip(".") + "."
        if needle.endswith(suffix) and len(suffix) > best_len:
            best = resolver
            best_len = len(suffix)
    if best is not None:
        return best
    return standard


async def fetch_scutil_dns() -> DnsInfo:
    """Run `scutil --dns` and parse the result."""
    completed = await anyio.run_process(
        ["/usr/sbin/scutil", "--dns"],
    )
    text = completed.stdout.decode("utf-8", errors="replace")
    return parse_scutil_dns(text)
