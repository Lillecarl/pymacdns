from __future__ import annotations

import contextlib
import errno
import ipaddress
import sys
from dataclasses import dataclass, field
from typing import Final

import anyio

from pymacdns import resolver as resolver_mod
from pymacdns import store as store_mod
from pymacdns.config import DEFAULT_CONFIG_PATH, DaemonSettings

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


async def serve_udp_sock(
    sock: anyio.abc.UDPSocket, state: DnsState
) -> None:
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


async def serve_tcp_listener(
    listener: anyio.abc.MultiListener[anyio.abc.SocketStream], state: DnsState
) -> None:
    await listener.serve(lambda stream: _tcp_connection(stream, state))


async def refresh_loop(
    state: DnsState, self_hosts: set[str], timeout: float, config_path: str
) -> None:
    async for snap in store_mod.watch(timeout, self_hosts, config_path):
        state.replace(snap)


async def hijack_loop(path: str, hosts: list[str], interval: float) -> None:
    wanted = "".join(f"nameserver {host}\n" for host in hosts)
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
    settings: DaemonSettings,
    config_path: str = DEFAULT_CONFIG_PATH,
    manage_resolv_conf: bool = True,
) -> None:
    state = DnsState()
    udp_socks: list[anyio.abc.UDPSocket] = []
    tcp_listeners: list[anyio.abc.MultiListener[anyio.abc.SocketStream]] = []
    bound: list[str] = []
    async with contextlib.AsyncExitStack() as stack:
        for host, port in settings.server.listen:
            udp_ok = tcp_ok = False
            try:
                sock = await anyio.create_udp_socket(local_host=host, local_port=port)
            except OSError as exc:
                print(_bind_hint(host, port, "UDP", exc), file=sys.stderr)
            else:
                await stack.enter_async_context(sock)
                udp_socks.append(sock)
                udp_ok = True
            try:
                listener = await anyio.create_tcp_listener(
                    local_host=host, local_port=port
                )
            except OSError as exc:
                print(_bind_hint(host, port, "TCP", exc), file=sys.stderr)
            else:
                await stack.enter_async_context(listener)
                tcp_listeners.append(listener)
                tcp_ok = True
            if udp_ok or tcp_ok:
                bound.append(host)
        if not udp_socks and not tcp_listeners:
            wanted = ", ".join(
                f"{host}:{port}" for host, port in settings.server.listen
            )
            raise RuntimeError(f"pymacdns: could not bind any of {wanted}")
        self_hosts = set(bound)
        async with anyio.create_task_group() as tg:
            for sock in udp_socks:
                tg.start_soon(serve_udp_sock, sock, state)
            for listener in tcp_listeners:
                tg.start_soon(serve_tcp_listener, listener, state)
            tg.start_soon(
                refresh_loop, state, self_hosts, settings.server.timeout, config_path
            )
            if manage_resolv_conf and bound:
                tg.start_soon(
                    hijack_loop, RESOLV_CONF, bound, settings.server.interval
                )


def _is_aliasable_loopback(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback and "." in host and host != "127.0.0.1"


def _bind_hint(host: str, port: int, proto: str, exc: OSError) -> str:
    what = f"pymacdns: {proto} {host}:{port}"
    if exc.errno == errno.EACCES:
        return f"{what}: permission denied (ports below 1024 need root)"
    if exc.errno == errno.EADDRINUSE:
        return f"{what}: already in use"
    if exc.errno == errno.EADDRNOTAVAIL and _is_aliasable_loopback(host):
        return f"{what}: missing loopback alias (sudo ifconfig lo0 alias {host} up)"
    if exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
        return f"{what}: address family unavailable (stack disabled?)"
    return f"{what}: {exc}"
