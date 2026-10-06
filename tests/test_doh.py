"""DNS-over-HTTPS: parsing, a live loopback exchange, and pooling."""

import anyio
import dns.message
import dns.rcode
import httpx
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


async def serve_doh(port: int, server_ctx) -> TLSListener:
    plain = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=port)
    return TLSListener(plain, server_ctx)


@pytest.mark.anyio
async def test_doh_loopback_verified_and_fail_closed():
    server_ctx, client_ctx = make_contexts()

    port = 18556
    listener = await serve_doh(port, server_ctx)
    wire = dns.message.make_query("example.com.", "A").to_wire()
    upstream = resolver_mod.Upstream(
        [f"https://127.0.0.1:{port}/dns-query"], timeout=10.0
    )
    async with httpx.AsyncClient(verify=client_ctx) as client:
        async with anyio.create_task_group() as tg:
            tg.start_soon(listener.serve, answer_doh)
            await anyio.sleep(0.2)
            reply = await resolver_mod.lookup(wire, upstream, doh_client=client)
            assert dns.message.from_wire(reply).rcode() == dns.rcode.NOERROR
            # No client, default trust: the unknown CA must fail the
            # query, not silently downgrade it.
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
        async with httpx.AsyncClient(verify=client_ctx) as client:
            async with plain_listener, udp_sock:
                async with anyio.create_task_group() as tg:
                    tg.start_soon(tls_listener.serve, answer_doh)
                    tg.start_soon(answer_plain_udp, udp_sock)
                    await anyio.sleep(0.2)
                    reply = await resolver_mod.lookup(
                        wire, upstream, doh_client=client
                    )
                    message = dns.message.from_wire(reply)
                    assert message.rcode() == dns.rcode.NOERROR
                    if expect_plain:
                        assert len(message.answer) == 1
                    else:
                        assert message.answer == []
                    tg.cancel_scope.cancel()


@pytest.mark.anyio
async def test_doh_client_pooled():
    """One shared client opens one connection; per-call clients dial each time."""
    server_ctx, client_ctx = make_contexts()

    port = 18559
    listener = await serve_doh(port, server_ctx)
    accepted: list[None] = []

    async def counting(stream: anyio.abc.SocketStream) -> None:
        accepted.append(None)
        await answer_doh(stream)

    wire = dns.message.make_query("example.com.", "A").to_wire()
    upstream = resolver_mod.Upstream(
        [f"https://127.0.0.1:{port}/dns-query"], timeout=10.0
    )
    async with anyio.create_task_group() as tg:
        tg.start_soon(listener.serve, counting)
        await anyio.sleep(0.2)
        async with httpx.AsyncClient(verify=client_ctx) as client:
            for _ in range(2):
                reply = await resolver_mod.lookup(wire, upstream, doh_client=client)
                assert dns.message.from_wire(reply).rcode() == dns.rcode.NOERROR
        assert len(accepted) == 1
        for _ in range(2):
            reply = await resolver_mod.lookup(
                wire, upstream, ssl_context=client_ctx
            )
            assert dns.message.from_wire(reply).rcode() == dns.rcode.NOERROR
        assert len(accepted) == 3
        tg.cancel_scope.cancel()
