from __future__ import annotations

import ipaddress
import subprocess
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

ROUTE_REFRESH_TTL: Final = 30.0
NETSTAT_TIMEOUT: Final = 5.0


class RouteFilter(StrEnum):
    """How aggressively to prune unroutable addresses from responses."""

    OFF = "off"
    FAMILY = "family"
    PREFIX = "prefix"


@dataclass
class RouteTable:
    """Parsed routing table used for routability checks."""

    nets: tuple[object, ...] = ()
    refreshed_at: float = 0.0

    def covers(self, address: object) -> bool:
        try:
            addr = ipaddress.ip_address(str(address))
        except ValueError:
            return True
        if (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_reserved
        ):
            return True
        return any(addr in net for net in self.nets)  # type: ignore[operator]

    def family_usable(self, version: int) -> bool:
        """Approximate AI_ADDRCONFIG: any non-scoped route of that family."""
        return any(
            net.version == version  # type: ignore[union-attr]
            and not net.is_loopback  # type: ignore[union-attr]
            and not net.is_link_local  # type: ignore[union-attr]
            and not net.is_multicast  # type: ignore[union-attr]
            for net in self.nets
        )

    def stale(
        self, now: float | None = None, ttl: float = ROUTE_REFRESH_TTL
    ) -> bool:
        return (now if now is not None else time.monotonic()) - self.refreshed_at > ttl


def parse_netstat(text: str) -> list[object]:
    """Parse `netstat -rn -f inet[6]` destinations into networks."""
    found: list[object] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        if parts[0] in ("Destination", "Routing", "Internet", "Internet6:"):
            continue
        dest = parts[0]
        if dest == "default":
            continue
        if "/" in dest:
            addr, _, prefix = dest.partition("/")
            dest = f"{addr.split('%')[0]}/{prefix}"
        else:
            dest = dest.split("%")[0]
        try:
            found.append(ipaddress.ip_network(dest, strict=False))
        except ValueError:
            continue
    return found


def has_default_route(text: str) -> bool:
    return any(line.split()[:1] == ["default"] for line in text.splitlines())


def read_system_routes() -> RouteTable:
    """Run netstat for both families. Blocking; call from a worker thread."""
    nets: list[object] = []
    for flag, default in (("inet", "0.0.0.0/0"), ("inet6", "::/0")):
        try:
            completed = subprocess.run(
                ["netstat", "-rn", "-f", flag],
                capture_output=True,
                text=True,
                timeout=NETSTAT_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode != 0:
            continue
        nets.extend(parse_netstat(completed.stdout))
        if has_default_route(completed.stdout):
            nets.append(ipaddress.ip_network(default))
    return RouteTable(nets=tuple(nets), refreshed_at=time.monotonic())


def _keep_address(address: object, table: RouteTable, mode: RouteFilter) -> bool:
    try:
        addr = ipaddress.ip_address(str(address))
    except ValueError:
        return True
    if mode == RouteFilter.FAMILY:
        return table.family_usable(addr.version)
    return table.covers(addr)


def filter_response(wire: bytes, table: RouteTable, mode: RouteFilter) -> bytes:
    """Prune unroutable A/AAAA addresses. Fail open on empty results."""
    if mode == RouteFilter.OFF:
        return wire
    try:
        response = dns.message.from_wire(wire)
    except Exception:
        return wire
    if response.rcode() != dns.rcode.NOERROR or not response.answer:
        return wire

    touched = False
    kept_rrsets = []
    for rrset in response.answer:
        if rrset.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
            kept_rrsets.append(rrset)
            continue
        kept = [r for r in rrset if _keep_address(r.address, table, mode)]
        if len(kept) != len(rrset):
            touched = True
        if not kept:
            continue
        if len(kept) == len(rrset):
            kept_rrsets.append(rrset)
            continue
        merged = None
        for rdata in kept:
            one = dns.rrset.from_rdata(rrset.name, rrset.ttl, rdata)
            if merged is None:
                merged = one
            else:
                merged.union_update(one)
        if merged is not None:
            kept_rrsets.append(merged)

    if not touched:
        return wire
    if not any(
        rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) for rrset in kept_rrsets
    ):
        return wire
    response.answer = kept_rrsets
    return response.to_wire()
