"""DNS-over-TLS: target parsing plus a live loopback exchange."""

import anyio
import dns.message
import dns.rcode
import pytest
from anyio.streams.tls import TLSListener
from helpers import answer_plain_udp, answer_tls, free_port, make_contexts

from pymacdns import resolver as resolver_mod


def test_split_target():
    split = resolver_mod._split_target
    assert split("9.9.9.9") == ("", "9.9.9.9", 53, "")
    assert split("9.9.9.9:5353") == ("", "9.9.9.9", 5353, "")
    assert split("[::1]:5353") == ("", "::1", 5353, "")
    assert split("tls://9.9.9.9") == ("tls", "9.9.9.9", 853, "")
    assert split("tls://dns.quad9.net") == ("tls", "dns.quad9.net", 853, "")
    assert split("tls://dns.quad9.net:8853") == ("tls", "dns.quad9.net", 8853, "")
    assert split("tls://[2620:fe::fe]") == ("tls", "2620:fe::fe", 853, "")
    assert split("https://9.9.9.9/dns-query") == (
        "https",
        "9.9.9.9",
        443,
        "/dns-query",
    )
    assert split("https://dns.quad9.net") == (
        "https",
        "dns.quad9.net",
        443,
        "/dns-query",
    )
    assert split("https://dns.quad9.net:8443/custom") == (
        "https",
        "dns.quad9.net",
        8443,
        "/custom",
    )
    with pytest.raises(ValueError):
        split("gopher://9.9.9.9")


@pytest.mark.anyio
async def test_lookup_rejects_unknown_scheme():
    wire = dns.message.make_query("example.com.", "A").to_wire()
    with pytest.raises(ValueError):
        await resolver_mod.lookup(
            wire, resolver_mod.Upstream(["gopher://9.9.9.9"])
        )

@pytest.mark.anyio
async def test_dot_loopback_verified_and_fail_closed():
    server_ctx, client_ctx = make_contexts()

    port = free_port()
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


@pytest.mark.anyio
async def test_listed_order_decides():
    """No magic priority: whoever is listed first wins when both work."""
    server_ctx, client_ctx = make_contexts()

    tls_port, plain_port = free_port(), free_port()
    wire = dns.message.make_query("example.com.", "A").to_wire()
    # The plaintext answer carries 192.0.2.1, the TLS one is empty:
    # whichever is listed first must be the one served.
    for nameservers, expect_plain in (
        ([f"127.0.0.1:{plain_port}", f"tls://127.0.0.1:{tls_port}"], True),
        ([f"tls://127.0.0.1:{tls_port}", f"127.0.0.1:{plain_port}"], False),
    ):
        plain_listener = await anyio.create_tcp_listener(
            local_host="127.0.0.1", local_port=tls_port
        )
        tls_listener = TLSListener(plain_listener, server_ctx)
        udp_sock = await anyio.create_udp_socket(
            local_host="127.0.0.1", local_port=plain_port
        )
        upstream = resolver_mod.Upstream(nameservers, timeout=5.0)
        async with plain_listener, udp_sock:
            async with anyio.create_task_group() as tg:
                tg.start_soon(tls_listener.serve, answer_tls)
                tg.start_soon(answer_plain_udp, udp_sock)
                await anyio.sleep(0.2)
                reply = await resolver_mod.lookup(
                    wire, upstream, ssl_context=client_ctx
                )
                message = dns.message.from_wire(reply)
                assert message.rcode() == dns.rcode.NOERROR
                if expect_plain:
                    assert len(message.answer) == 1
                else:
                    assert message.answer == []
                tg.cancel_scope.cancel()
