"""Upstream health: probe every effective upstream across names and types.

DNSSEC is exercised, not implemented: the daemon forwards the DO bit
untouched and never validates, so validation is the upstream's job.
The last two probes are the control pair: sigok is correctly signed
and must answer NOERROR, dnssec-failed.org is bogus on purpose and a
validating upstream (Quad9) must SERVFAIL it. Both verdicts pass
straight through.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass, field

import anyio
import dns.exception
import dns.message
import dns.rcode
import httpx

from pymacdns import resolver as resolver_mod
from pymacdns import store as store_mod


@dataclass(frozen=True)
class Probe:
    name: str
    qtype: str


@dataclass(frozen=True)
class Target:
    scope: str
    nameserver: str


@dataclass
class Outcome:
    latency_ms: float | None = None
    rcode: str | None = None
    error: str | None = None

    def cell(self) -> str:
        if self.latency_ms is not None:
            return f"{self.latency_ms:.0f}ms"
        if self.rcode is not None:
            return self.rcode
        if self.error is not None:
            return self.error
        return "-"


@dataclass
class Row:
    target: Target
    outcomes: dict[Probe, Outcome] = field(default_factory=dict)


# example.com covers the common types against one zone; ipv6.google
# is AAAA-only; the last two are the DNSSEC control pair, valid and
# bogus on purpose.
PROBES: tuple[Probe, ...] = (
    Probe("example.com.", "A"),
    Probe("example.com.", "AAAA"),
    Probe("example.com.", "MX"),
    Probe("example.com.", "TXT"),
    Probe("example.com.", "SOA"),
    Probe("example.com.", "NS"),
    Probe("example.com.", "DNSKEY"),
    Probe("ipv6.google.com.", "AAAA"),
    Probe("sigok.verteiltesysteme.net.", "A"),
    Probe("dnssec-failed.org.", "A"),
)


def describe_targets(snap: store_mod.Snapshot) -> list[Target]:
    """Distinct targets: scope is the routing domain, or default."""
    targets: list[Target] = []
    seen: set[Target] = set()

    def add(scope: str, nameservers: list[str]) -> None:
        for ns in nameservers:
            target = Target(scope, ns)
            if target not in seen:
                seen.add(target)
                targets.append(target)

    if snap.standard is not None:
        add("default", snap.standard.nameservers)
    for domain in sorted(snap.domains):
        add(domain, snap.domains[domain].nameservers)
    return targets


def column_labels(probes: tuple[Probe, ...] = PROBES) -> list[str]:
    """Header labels: every column names the probe it runs."""
    return [f"{probe.name.split('.')[0]}:{probe.qtype}" for probe in probes]


async def probe_one(
    nameserver: str,
    probe: Probe,
    timeout: float,
    found: list[tuple[str, Probe, Outcome]],
    ssl_context: ssl.SSLContext | None = None,
    doh_client: httpx.AsyncClient | None = None,
) -> None:
    start = time.monotonic()
    try:
        query = dns.message.make_query(probe.name, probe.qtype)
        reply = await resolver_mod.lookup(
            query.to_wire(),
            resolver_mod.Upstream([nameserver], timeout),
            ssl_context=ssl_context,
            doh_client=doh_client,
        )
        rcode = dns.message.from_wire(reply).rcode()
        if rcode == dns.rcode.NOERROR:
            outcome = Outcome(latency_ms=(time.monotonic() - start) * 1000.0)
        else:
            outcome = Outcome(rcode=dns.rcode.to_text(rcode))
    except (TimeoutError, dns.exception.Timeout):
        outcome = Outcome(error="timeout")
    except OSError:
        outcome = Outcome(error="conn")
    except ValueError:
        outcome = Outcome(error="bad")
    except Exception:  # noqa: BLE001 - one bad probe must not kill the table
        outcome = Outcome(error="err")
    found.append((nameserver, probe, outcome))


async def check(
    targets: list[Target],
    timeout: float,
    probes: tuple[Probe, ...] = PROBES,
    ssl_context: ssl.SSLContext | None = None,
    doh_client: httpx.AsyncClient | None = None,
) -> list[Row]:
    """Probe every target across every probe concurrently, in order."""
    found: list[tuple[str, Probe, Outcome]] = []
    async with anyio.create_task_group() as tg:
        for target in targets:
            for probe in probes:
                tg.start_soon(
                    probe_one,
                    target.nameserver,
                    probe,
                    timeout,
                    found,
                    ssl_context,
                    doh_client,
                )
    by_nameserver = {(ns, probe): outcome for ns, probe, outcome in found}
    return [
        Row(
            target,
            {
                probe: by_nameserver.get((target.nameserver, probe), Outcome())
                for probe in probes
            },
        )
        for target in targets
    ]


def render(rows: list[Row], probes: tuple[Probe, ...] = PROBES) -> str:
    """Align the matrix: one row per upstream, one column per probe."""
    head = ["UPSTREAM", "SCOPE"] + column_labels(probes)
    table = [head]
    for row in rows:
        table.append(
            [row.target.nameserver, row.target.scope]
            + [row.outcomes.get(probe, Outcome()).cell() for probe in probes]
        )
    widths = [max(len(line[i]) for line in table) for i in range(len(head))]
    lines = [
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(line)).rstrip()
        for line in table
    ]
    return "\n".join(lines)
