"""DNS-over-TLS: target parsing plus a live loopback exchange."""

import ssl

import anyio
import dns.message
import dns.rcode
import pytest
import trustme
from anyio.streams.tls import TLSListener

from pymacdns import resolver as resolver_mod


def test_split_target():
    split = resolver_mod._split_target
    assert split("9.9.9.9") == ("", "9.9.9.9", 53)
    assert split("9.9.9.9:5353") == ("", "9.9.9.9", 5353)
    assert split("[::1]:5353") == ("", "::1", 5353)
    assert split("tls://9.9.9.9") == ("tls", "9.9.9.9", 853)
    assert split("tls://dns.quad9.net") == ("tls", "dns.quad9.net", 853)
    assert split("tls://dns.quad9.net:8853") == ("tls", "dns.quad9.net", 8853)
    assert split("tls://[2620:fe::fe]") == ("tls", "2620:fe::fe", 853)
    with pytest.raises(ValueError):
        split("https://dns.quad9.net/dns-query")


def test_lookup_rejects_unknown_scheme():
    wire = dns.message.make_query("example.com.", "A").to_wire()
    with pytest.raises(ValueError):
        anyio.run(
            resolver_mod.lookup,
            wire,
            resolver_mod.Upstream(["https://dns.quad9.net/dns-query"]),
        )


async def answer_tls(stream: anyio.abc.SocketStream) -> None:
    async with stream:
        while True:
            try:
                header = await stream.receive(2)
            except anyio.EndOfStream:
                return
            while len(header) < 2:
                header += await stream.receive(2 - len(header))
            length = int.from_bytes(header, "big")
            body = b""
            while len(body) < length:
                try:
                    body += await stream.receive(length - len(body))
                except anyio.EndOfStream:
                    return
            request = dns.message.from_wire(body)
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)
            reply = response.to_wire()
            await stream.send(len(reply).to_bytes(2, "big") + reply)


@pytest.mark.anyio
async def test_dot_loopback_verified_and_fail_closed():
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)
    client_ctx = ssl.create_default_context()
    ca.configure_trust(client_ctx)

    port = 18553
    plain = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=port)
    listener = TLSListener(plain, server_ctx)
    wire = dns.message.make_query("example.com.", "A").to_wire()
    upstream = resolver_mod.Upstream([f"tls://127.0.0.1:{port}"], timeout=5.0)
    async with anyio.create_task_group() as tg:
        tg.start_soon(listener.serve, answer_tls)
        await anyio.sleep(0.2)
        reply = await resolver_mod.lookup(wire, upstream, ssl_context=client_ctx)
        assert dns.message.from_wire(reply).rcode() == dns.rcode.NOERROR
        # The system trust store knows nothing of this CA: without our
        # context the same endpoint must fail, not silently downgrade.
        with pytest.raises(Exception):
            await resolver_mod.lookup(wire, upstream)
        tg.cancel_scope.cancel()
