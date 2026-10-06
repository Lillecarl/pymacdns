"""Upstream health: probe every effective upstream across names and types.

DNSSEC is exercised, not implemented: the daemon forwards the DO bit
untouched and never validates, so validation is the upstream's job.
The dnssec-failed.org probe proves it: a validating upstream (Quad9)
SERVFAILs its bogus signature, and that answer passes straight through.
"""

from __future__ import annotations

import ssl
import time

import anyio
import dns.exception
import dns.message
import dns.rcode
import httpx

from pymacdns import resolver as resolver_mod
from pymacdns import store as store_mod

# (name, type) pairs. example.com covers the common types against one
# zone; the last two are diagnostics: a AAAA-only name and a name
# whose signature is bogus on purpose.
PROBES: tuple[tuple[str, str], ...] = (
    ("example.com.", "A"),
    ("example.com.", "AAAA"),
    ("example.com.", "MX"),
    ("example.com.", "TXT"),
    ("example.com.", "SOA"),
    ("example.com.", "NS"),
    ("example.com.", "DNSKEY"),
    ("ipv6.google.com.", "AAAA"),
    ("dnssec-failed.org.", "A"),
)


def describe_targets(snap: store_mod.Snapshot) -> list[tuple[str, str]]:
    """Distinct (scope, nameserver) rows: scope is the routing domain or default."""
    rows: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(scope: str, nameservers: list[str]) -> None:
        for ns in nameservers:
            if (scope, ns) not in seen:
                seen.add((scope, ns))
                rows.append((scope, ns))

    if snap.standard is not None:
        add("default", snap.standard.nameservers)
    for domain in sorted(snap.domains):
        add(domain, snap.domains[domain].nameservers)
    return rows


def cell_for(result: object) -> str:
    """Render one probe outcome: latency, rcode, or short error."""
    if isinstance(result, float):
        return f"{result:.0f}ms"
    return str(result)


async def probe_one(
    nameserver: str,
    name: str,
    qtype: str,
    timeout: float,
    results: dict[tuple[str, tuple[str, str]], object],
    ssl_context: ssl.SSLContext | None = None,
    doh_client: httpx.AsyncClient | None = None,
) -> None:
    key = (nameserver, (name, qtype))
    start = time.monotonic()
    try:
        query = dns.message.make_query(name, qtype)
        reply = await resolver_mod.lookup(
            query.to_wire(),
            resolver_mod.Upstream([nameserver], timeout),
            ssl_context=ssl_context,
            doh_client=doh_client,
        )
        rcode = dns.message.from_wire(reply).rcode()
        if rcode == dns.rcode.NOERROR:
            results[key] = (time.monotonic() - start) * 1000.0
        else:
            results[key] = dns.rcode.to_text(rcode)
    except (TimeoutError, dns.exception.Timeout):
        results[key] = "timeout"
    except OSError:
        results[key] = "conn"
    except ValueError:
        results[key] = "bad"
    except Exception:  # noqa: BLE001 - one bad probe must not kill the table
        results[key] = "err"


async def check(
    nameservers: list[str],
    timeout: float,
    probes: tuple[tuple[str, str], ...] = PROBES,
    ssl_context: ssl.SSLContext | None = None,
    doh_client: httpx.AsyncClient | None = None,
) -> dict[tuple[str, tuple[str, str]], object]:
    """Probe every nameserver across every probe concurrently."""
    results: dict[tuple[str, tuple[str, str]], object] = {}
    async with anyio.create_task_group() as tg:
        for ns in nameservers:
            for name, qtype in probes:
                tg.start_soon(
                    probe_one,
                    ns,
                    name,
                    qtype,
                    timeout,
                    results,
                    ssl_context,
                    doh_client,
                )
    return results


def render(
    rows: list[tuple[str, str]],
    results: dict[tuple[str, tuple[str, str]], object],
    probes: tuple[tuple[str, str], ...] = PROBES,
) -> str:
    """Align the matrix: one row per upstream, one column per probe."""
    head = ["UPSTREAM", "SCOPE"] + [qtype for _, qtype in probes]
    table = [head]
    for scope, ns in rows:
        table.append(
            [ns, scope]
            + [cell_for(results.get((ns, probe), "-")) for probe in probes]
        )
    widths = [max(len(row[i]) for row in table) for i in range(len(head))]
    lines = [
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        for row in table
    ]
    return "\n".join(lines)
