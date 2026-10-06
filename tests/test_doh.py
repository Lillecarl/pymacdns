"""DNS-over-HTTPS: parsing, a live loopback exchange, and priority."""

import anyio
import dns.message
import dns.rcode
import pytest
from anyio.streams.tls import TLSListener
from helpers import answer_doh, answer_plain_udp, make_contexts

from pymacdns import resolver as resolver_mod


def test_split_target_https():
    split = resolver_mod._split_target
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
    assert split("https://[2620:fe::9]/dns-query") == (
        "https",
        "2620:fe::9",
        443,
        "/dns-query",
    )


@pytest.mark.anyio
async def test_doh_loopback_verified_and_fail_closed():
    server_ctx, client_ctx = make_contexts()

    port = 18556
    plain = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=port)
    listener = TLSListener(plain, server_ctx)
    wire = dns.message.make_query("example.com.", "A").to_wire()
    upstream = resolver_mod.Upstream(
        [f"https://127.0.0.1:{port}/dns-query"], timeout=10.0
    )
    async with anyio.create_task_group() as tg:
        tg.start_soon(listener.serve, answer_doh)
        await anyio.sleep(0.2)
        reply = await resolver_mod.lookup(wire, upstream, ssl_context=client_ctx)
        assert dns.message.from_wire(reply).rcode() == dns.rcode.NOERROR
        with pytest.raises(Exception):
            await resolver_mod.lookup(wire, upstream)
        tg.cancel_scope.cancel()


@pytest.mark.anyio
async def test_listed_order_decides():
    """No magic priority: whoever is listed first wins when both work."""
    server_ctx, client_ctx = make_contexts()

    tls_port, plain_port = 18557, 18558
    wire = dns.message.make_query("example.com.", "A").to_wire()
    for nameservers, expect_plain in (
        ([f"127.0.0.1:{plain_port}", f"https://127.0.0.1:{tls_port}/dns-query"], True),
        ([f"https://127.0.0.1:{tls_port}/dns-query", f"127.0.0.1:{plain_port}"], False),
    ):
        plain_listener = await anyio.create_tcp_listener(
            local_host="127.0.0.1", local_port=tls_port
        )
        tls_listener = TLSListener(plain_listener, server_ctx)
        udp_sock = await anyio.create_udp_socket(
            local_host="127.0.0.1", local_port=plain_port
        )
        upstream = resolver_mod.Upstream(nameservers, timeout=10.0)
        async with plain_listener, udp_sock:
            async with anyio.create_task_group() as tg:
                tg.start_soon(tls_listener.serve, answer_doh)
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
