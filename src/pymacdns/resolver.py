from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass
from typing import Final

import anyio
import dns.asyncquery
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import httpx

DEFAULT_TIMEOUT: Final = 2.0

# Namespaces owned by multicast DNS (RFC 6762) or otherwise reserved.
# A unicast forwarder must never claim them: REFUSED keeps native
# clients on their mDNS path and fails direct clients fast without
# caching a false negative.
REFUSED_SUFFIXES: Final = (
    "local.",
    "254.169.in-addr.arpa.",
    "8.e.f.ip6.arpa.",
    "9.e.f.ip6.arpa.",
    "a.e.f.ip6.arpa.",
    "b.e.f.ip6.arpa.",
)
LOCALHOST_TTL: Final = 120


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


def special_response(wire: bytes) -> bytes | None:
    """Answer reserved names locally, else None meaning forward upstream.

    .local and mDNS reverse zones get REFUSED, .invalid gets NXDOMAIN
    per RFC 2606, and .localhost resolves to loopback per RFC 6761.
    """
    request = dns.message.from_wire(wire)
    if not request.question:
        raise ValueError("DNS message has no question")
    question = request.question[0]
    qname = str(question.name).lower()
    qtype = question.rdtype

    if qname == "localhost." or qname.endswith(".localhost."):
        response = dns.message.make_response(request)
        if qtype in (dns.rdatatype.A, dns.rdatatype.ANY):
            response.answer.append(
                dns.rrset.from_text(
                    question.name, LOCALHOST_TTL, "IN", "A", "127.0.0.1"
                )
            )
        if qtype in (dns.rdatatype.AAAA, dns.rdatatype.ANY):
            response.answer.append(
                dns.rrset.from_text(question.name, LOCALHOST_TTL, "IN", "AAAA", "::1")
            )
        return response.to_wire()
    if qname == "invalid." or qname.endswith(".invalid."):
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()
    if qname in REFUSED_SUFFIXES or any(
        qname.endswith("." + suffix) for suffix in REFUSED_SUFFIXES
    ):
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()
    return None


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


async def forward_tls(
    wire: bytes,
    host: str,
    port: int,
    timeout: float,
    ssl_context: ssl.SSLContext | None = None,
) -> bytes:
    """DNS-over-TLS: length-prefixed query over a verified TLS stream.

    The host doubles as the TLS name: SNI is always sent (some servers
    fail without it) and the certificate must cover it. Quad9's covers
    its names and its anycast IPs alike, so tls://9.9.9.9 verifies with
    no bootstrap lookup.
    """
    with anyio.fail_after(timeout):
        stream = await anyio.connect_tcp(
            host, port, tls=True, tls_hostname=host, ssl_context=ssl_context
        )
        async with stream:
            prefix = len(wire).to_bytes(2, "big")
            await stream.send(prefix + wire)
            header = await stream.receive(2)
            while len(header) < 2:
                header += await stream.receive(2 - len(header))
            length = int.from_bytes(header, "big")
            data = b""
            while len(data) < length:
                data += await stream.receive(length - len(data))
            return data


def _split_hostport(nameserver: str, default_port: int = 53) -> tuple[str, int]:
    """Split 'host', 'host:port', or '[v6]:port'.

    Bare IPs (v4 or v6, including scoped v6 like fe80::1%en0) are
    detected with ipaddress and returned with the default port.
    """
    ns = nameserver.strip()
    if ns.startswith("["):
        host, _, rest = ns[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else default_port
    try:
        ipaddress.ip_address(ns)
        return ns, default_port
    except ValueError:
        pass
    host, sep, port = ns.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return ns, default_port


def _split_target(nameserver: str) -> tuple[str, str, int, str]:
    """Split '[scheme://]host[:port][/path]' into (scheme, host, port, path).

    Only plain DNS, tls:// (default 853) and https:// (default 443,
    default path /dns-query) exist; anything else raises instead of
    silently downgrading to cleartext.
    """
    text = nameserver.strip()
    scheme, sep, rest = text.partition("://")
    if not sep:
        scheme, rest = "", text
    if scheme not in ("", "tls", "https"):
        raise ValueError(f"unknown upstream scheme in {nameserver!r}")
    authority, slash, raw_path = rest.partition("/")
    if scheme == "tls":
        default_port = 853
    elif scheme == "https":
        default_port = 443
    else:
        default_port = 53
    host, port = _split_hostport(authority, default_port)
    path = "/" + raw_path if slash else ("/dns-query" if scheme == "https" else "")
    return scheme, host, port, path


async def forward_doh(
    wire: bytes,
    host: str,
    port: int,
    path: str,
    timeout: float,
    client: httpx.AsyncClient | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> bytes:
    """DNS-over-HTTPS via dnspython: POST of the wire query, verified.

    An IP host verifies against its SANs with no bootstrap lookup;
    a name resolves through the system (so /etc/hosts works). A shared
    client pools connections and carries its own verification; without
    one dnspython dials per query, verified by the given context or by
    default when it is None.
    """
    query = dns.message.from_wire(wire)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    url = f"https://{host}:{port}{path or '/dns-query'}"
    verify = True if ssl_context is None else ssl_context
    response = await dns.asyncquery.https(
        query, url, timeout=timeout, post=True, client=client, verify=verify
    )
    return response.to_wire()


async def lookup(
    wire: bytes,
    upstream: Upstream,
    use_tcp: bool = False,
    ssl_context: ssl.SSLContext | None = None,
    doh_client: httpx.AsyncClient | None = None,
) -> bytes:
    """Forward to upstreams in listed order, return the first success.

    Priority lives in the configuration, not here: whoever lists the
    nameservers decides the order, encrypted or otherwise. Unknown
    schemes are skipped, never downgraded.
    """
    last_error: Exception | None = None
    for nameserver in upstream.nameservers:
        try:
            scheme, host, port, path = _split_target(nameserver)
        except ValueError as exc:
            last_error = exc
            continue
        try:
            if scheme == "tls":
                return await forward_tls(
                    wire, host, port, upstream.timeout, ssl_context
                )
            if scheme == "https":
                return await forward_doh(
                    wire,
                    host,
                    port,
                    path,
                    upstream.timeout,
                    doh_client,
                    ssl_context,
                )
            if use_tcp:
                return await forward_tcp(wire, host, port, upstream.timeout)
            return await forward_udp(wire, host, port, upstream.timeout)
        except Exception as exc:  # noqa: BLE001 - try next upstream
            last_error = exc
            continue
    if last_error is not None:
        raise last_error
    raise RuntimeError("no upstreams configured")
