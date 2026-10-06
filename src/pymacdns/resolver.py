from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Final

import anyio
import dns.message

DEFAULT_TIMEOUT: Final = 2.0


@dataclass
class Upstream:
    nameservers: list[str]
    timeout: float = DEFAULT_TIMEOUT


def build_upstream(nameservers: list[str], timeout: float) -> Upstream:
    return Upstream(nameservers=list(nameservers), timeout=timeout)


def pick_upstream(
    qname: str,
    domains: dict[str, Upstream],
    standard: Upstream | None,
) -> Upstream | None:
    """Longest-suffix match, case-insensitive."""
    needle = qname.lower()
    if not needle.endswith("."):
        needle += "."
    best: Upstream | None = None
    best_len = -1
    for domain, upstream in domains.items():
        suffix = domain.lower().rstrip(".") + "."
        if needle.endswith(suffix) and len(suffix) > best_len:
            best = upstream
            best_len = len(suffix)
    return best if best is not None else standard


def question_name(wire: bytes) -> str:
    msg = dns.message.from_wire(wire)
    if not msg.question:
        raise ValueError("DNS message has no question")
    return str(msg.question[0].name)


def servfail(wire: bytes) -> bytes:
    request = dns.message.from_wire(wire)
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.SERVFAIL)
    return response.to_wire()


async def forward_udp(wire: bytes, host: str, port: int, timeout: float) -> bytes:
    sock = await anyio.create_connected_udp_socket(host, port)
    async with sock:
        await sock.send(wire)
        with anyio.fail_after(timeout):
            return await sock.receive()


async def forward_tcp(wire: bytes, host: str, port: int, timeout: float) -> bytes:
    stream = await anyio.connect_tcp(host, port)
    async with stream:
        prefix = len(wire).to_bytes(2, "big")
        with anyio.fail_after(timeout):
            await stream.send(prefix + wire)
            header = await stream.receive(2)
            while len(header) < 2:
                header += await stream.receive(2 - len(header))
            length = int.from_bytes(header, "big")
            data = b""
            while len(data) < length:
                data += await stream.receive(length - len(data))
            return data


def _split_hostport(nameserver: str) -> tuple[str, int]:
    """Split 'host', 'host:port', or '[v6]:port'.

    Bare IPs (v4 or v6, including scoped v6 like fe80::1%en0) are
    detected with ipaddress and returned with the default port.
    """
    ns = nameserver.strip()
    if ns.startswith("["):
        host, _, rest = ns[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else 53
    try:
        ipaddress.ip_address(ns)
        return ns, 53
    except ValueError:
        pass
    host, sep, port = ns.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return ns, 53


async def lookup(
    wire: bytes,
    upstream: Upstream,
    use_tcp: bool = False,
) -> bytes:
    """Forward to upstreams in order, return the first success."""
    last_error: Exception | None = None
    for nameserver in upstream.nameservers:
        host, port = _split_hostport(nameserver)
        try:
            if use_tcp:
                return await forward_tcp(wire, host, port, upstream.timeout)
            return await forward_udp(wire, host, port, upstream.timeout)
        except Exception as exc:  # noqa: BLE001 - try next upstream
            last_error = exc
            continue
    if last_error is not None:
        raise last_error
    raise RuntimeError("no upstreams configured")
