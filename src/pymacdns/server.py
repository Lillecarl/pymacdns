from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

import anyio

from pymacdns import resolver as resolver_mod
from pymacdns import store as store_mod

DEFAULT_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 53
DEFAULT_INTERVAL: Final = 1.0
RESOLV_CONF: Final = "/etc/resolv.conf"


@dataclass
class DnsState:
    standard: resolver_mod.Upstream | None = None
    domains: dict[str, resolver_mod.Upstream] = field(default_factory=dict)

    def pick(self, qname: str) -> resolver_mod.Upstream | None:
        return resolver_mod.pick_upstream(qname, self.domains, self.standard)

    def replace(self, snap: store_mod.Snapshot) -> None:
        self.standard = snap.standard
        self.domains = dict(snap.domains)


async def handle_wire(wire: bytes, state: DnsState, use_tcp: bool) -> bytes:
    try:
        qname = resolver_mod.question_name(wire)
    except Exception:
        raise ValueError("unparseable DNS query")
    upstream = state.pick(qname)
    if upstream is None:
        return resolver_mod.servfail(wire)
    try:
        return await resolver_mod.lookup(wire, upstream, use_tcp=use_tcp)
    except Exception:
        return resolver_mod.servfail(wire)


async def serve_udp(host: str, port: int, state: DnsState) -> None:
    sock = await anyio.create_udp_socket(local_host=host, local_port=port)
    async with sock, anyio.create_task_group() as tg:
        while True:
            data, addr = await sock.receive()

            async def _one(data: bytes = data, addr: tuple[str, int] = addr) -> None:
                try:
                    reply = await handle_wire(data, state, use_tcp=False)
                except ValueError:
                    return
                await sock.sendto(reply, addr[0], addr[1])

            tg.start_soon(_one)


async def _tcp_connection(stream: anyio.abc.SocketStream, state: DnsState) -> None:
    async with stream:
        buf = b""
        while True:
            while len(buf) < 2:
                chunk = await stream.receive(2 - len(buf))
                if not chunk:
                    return
                buf += chunk
            length = int.from_bytes(buf[:2], "big")
            buf = buf[2:]
            while len(buf) < length:
                chunk = await stream.receive(length - len(buf))
                if not chunk:
                    return
                buf += chunk
            wire, buf = buf[:length], buf[length:]
            try:
                reply = await handle_wire(wire, state, use_tcp=True)
            except ValueError:
                return
            await stream.send(len(reply).to_bytes(2, "big") + reply)


async def serve_tcp(host: str, port: int, state: DnsState) -> None:
    listener = await anyio.create_tcp_listener(local_host=host, local_port=port)
    await listener.serve(lambda stream: _tcp_connection(stream, state))


async def refresh_loop(state: DnsState, self_hosts: set[str], timeout: float) -> None:
    async for snap in store_mod.watch(timeout, self_hosts):
        state.replace(snap)


async def hijack_loop(path: str, host: str, interval: float) -> None:
    wanted = f"nameserver {host}\n"
    target = anyio.Path(path)
    while True:
        try:
            try:
                current = await target.read_text()
            except FileNotFoundError:
                current = ""
            if current != wanted:
                await target.write_text(wanted)
        except OSError:  # noqa: BLE001 - e.g. no permission, retry next tick
            pass
        await anyio.sleep(interval)


async def run(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = resolver_mod.DEFAULT_TIMEOUT,
    interval: float = DEFAULT_INTERVAL,
    manage_resolv_conf: bool = True,
) -> None:
    state = DnsState()
    self_hosts = {"127.0.0.1", "::1", host}
    async with anyio.create_task_group() as tg:
        tg.start_soon(serve_udp, host, port, state)
        tg.start_soon(serve_tcp, host, port, state)
        tg.start_soon(refresh_loop, state, self_hosts, timeout)
        if manage_resolv_conf:
            tg.start_soon(hijack_loop, RESOLV_CONF, host, interval)
