"""End-to-end through the real server with a fake upstream.

No internet needed: a local stub answers A queries for example.com
and NXDOMAIN otherwise, and can be switched off to prove stale-while-
error serving.
"""

import anyio
import dns.message
import dns.rcode
import dns.rrset
import pytest

from pymacdns import cache as cache_mod
from pymacdns import resolver as resolver_mod
from pymacdns import server as server_mod


class FakeUpstream:
    def __init__(self, port: int) -> None:
        self.port = port
        self.enabled = True

    def answer(self, wire: bytes) -> bytes | None:
        if not self.enabled:
            return None
        request = dns.message.from_wire(wire)
        response = dns.message.make_response(request)
        qname = str(request.question[0].name)
        if qname == "example.com." and request.question[0].rdtype == 1:
            response.answer.append(
                dns.rrset.from_text("example.com.", 300, "IN", "A", "93.184.216.34")
            )
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()

    async def run_udp(self) -> None:
        sock = await anyio.create_udp_socket(
            local_host="127.0.0.1", local_port=self.port
        )
        async with sock:
            while True:
                data, addr = await sock.receive()
                reply = self.answer(data)
                if reply is not None:
                    await sock.sendto(reply, addr[0], addr[1])

    async def run_tcp(self) -> None:
        listener = await anyio.create_tcp_listener(
            local_host="127.0.0.1", local_port=self.port
        )
        await listener.serve(self._tcp_connection)

    async def _tcp_connection(self, stream) -> None:
        async with stream:
            while True:
                try:
                    header = await stream.receive(2)
                except anyio.EndOfStream:
                    return
                if len(header) < 2:
                    return
                length = int.from_bytes(header, "big")
                body = b""
                while len(body) < length:
                    try:
                        chunk = await stream.receive(length - len(body))
                    except anyio.EndOfStream:
                        return
                    body += chunk
                reply = self.answer(body)
                if reply is not None:
                    await stream.send(len(reply).to_bytes(2, "big") + reply)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.anyio
async def test_full_path():
    clock = Clock()
    fake = FakeUpstream(15371)
    state = server_mod.DnsState()
    state.cache = cache_mod.DnsCache(clock=clock)
    state.standard = resolver_mod.Upstream(
        nameservers=["127.0.0.1:15371"], timeout=1.0
    )
    ours = 15372

    async def ask(name, qtype="A", tcp=False):
        q = dns.message.make_query(name, qtype).to_wire()
        if tcp:
            stream = await anyio.connect_tcp("127.0.0.1", ours)
            async with stream:
                await stream.send(len(q).to_bytes(2, "big") + q)
                header = await stream.receive(2)
                body = await stream.receive(int.from_bytes(header, "big"))
                return dns.message.from_wire(body)
        sock = await anyio.create_connected_udp_socket("127.0.0.1", ours)
        async with sock:
            await sock.send(q)
            return dns.message.from_wire(await sock.receive())

    async with anyio.create_task_group() as tg:
        tg.start_soon(fake.run_udp)
        tg.start_soon(fake.run_tcp)
        udp_sock = await anyio.create_udp_socket(
            local_host="127.0.0.1", local_port=ours
        )
        tcp_listener = await anyio.create_tcp_listener(
            local_host="127.0.0.1", local_port=ours
        )
        tg.start_soon(server_mod.serve_udp_sock, udp_sock, state)
        tg.start_soon(server_mod.serve_tcp_listener, tcp_listener, state)
        await anyio.sleep(0.3)

        resp = await ask("example.com.")
        assert dns.rcode.to_text(resp.rcode()) == "NOERROR"
        assert [r.address for rr in resp.answer for r in rr] == ["93.184.216.34"]
        assert [rr.ttl for rr in resp.answer] == [10]

        resp = await ask("example.com.", tcp=True)
        assert dns.rcode.to_text(resp.rcode()) == "NOERROR"

        resp = await ask("printer.local.")
        assert dns.rcode.to_text(resp.rcode()) == "REFUSED"

        # Kill the upstream: fresh cache serves silently, stale serves on.
        fake.enabled = False
        resp = await ask("example.com.")
        assert [r.address for rr in resp.answer for r in rr] == ["93.184.216.34"]
        clock.now += 500
        resp = await ask("example.com.")
        assert dns.rcode.to_text(resp.rcode()) == "NOERROR"
        assert [r.address for rr in resp.answer for r in rr] == ["93.184.216.34"]

        tg.cancel_scope.cancel()
