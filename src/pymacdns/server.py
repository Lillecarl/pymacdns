from __future__ import annotations

import contextlib
import errno
import ipaddress
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

import anyio
import dns.message
import dns.rcode
import httpx

from pymacdns import cache as cache_mod
from pymacdns import control as control_mod
from pymacdns import interfaces as interfaces_mod
from pymacdns import latency as latency_mod
from pymacdns import resolver as resolver_mod
from pymacdns import routes as routes_mod
from pymacdns import store as store_mod
from pymacdns.config import DEFAULT_CONFIG_PATH, DaemonSettings


@dataclass
class DnsState:
    standard: resolver_mod.Upstream | None = None
    domains: dict[str, resolver_mod.Upstream] = field(default_factory=dict)
    routes: routes_mod.RouteTable = field(default_factory=routes_mod.RouteTable)
    route_filter: routes_mod.RouteFilter = routes_mod.RouteFilter.OFF
    cache: cache_mod.DnsCache = field(default_factory=cache_mod.DnsCache)
    doh_client: httpx.AsyncClient | None = None
    latency: latency_mod.LatencyStats = field(
        default_factory=latency_mod.LatencyStats
    )

    def pick(self, qname: str) -> resolver_mod.Upstream | None:
        return resolver_mod.pick_upstream(qname, self.domains, self.standard)

    def replace(self, snap: store_mod.Snapshot) -> None:
        self.standard = snap.standard
        self.domains = dict(snap.domains)


def finalize(stored: bytes, qid: int, state: DnsState) -> bytes:
    """Filter, TTL-cap, and stamp the query ID onto a served response."""
    filtered = routes_mod.filter_response(stored, state.routes, state.route_filter)
    capped = cache_mod.cap_ttls(filtered)
    try:
        response = dns.message.from_wire(capped)
    except Exception:
        return capped
    response.id = qid
    return response.to_wire()


async def handle_wire(wire: bytes, state: DnsState, use_tcp: bool) -> bytes:
    try:
        special = resolver_mod.special_response(wire)
    except Exception:
        raise ValueError("unparseable DNS query")
    if special is not None:
        return cache_mod.cap_ttls(special)
    try:
        request = dns.message.from_wire(wire)
        key = cache_mod.key_of(wire)
    except Exception:
        raise ValueError("unparseable DNS query")
    entry = state.cache.get(key)
    if entry is not None and not entry.dead(state.cache.clock()):
        return finalize(entry.wire, request.id, state)
    upstream = state.pick(key.name)
    reply: bytes | None = None
    try:
        if upstream is None:
            raise ValueError("no upstream")
        reply = await resolver_mod.lookup(
            wire,
            upstream,
            use_tcp=use_tcp,
            doh_client=state.doh_client,
            stats=state.latency,
        )
        if dns.message.from_wire(reply).rcode() not in (
            dns.rcode.NOERROR,
            dns.rcode.NXDOMAIN,
        ):
            raise ValueError("upstream error")
    except Exception:
        if entry is not None:
            return finalize(entry.wire, request.id, state)
        return reply if reply is not None else resolver_mod.servfail(wire)
    state.cache.store(key, reply)
    return finalize(reply, request.id, state)


async def serve_udp_sock(
    sock: anyio.abc.UDPSocket, state: DnsState
) -> None:
    # anyio allows one writer per socket and raises BusyResourceError on a
    # second, which takes the whole server down under concurrent queries.
    send_lock = anyio.Lock()
    async with sock, anyio.create_task_group() as tg:
        while True:
            data, addr = await sock.receive()

            async def _one(data: bytes = data, addr: tuple[str, int] = addr) -> None:
                try:
                    reply = await handle_wire(data, state, use_tcp=False)
                except ValueError:
                    return
                async with send_lock:
                    # A lost UDP reply is the client's to retry, never a
                    # reason to stop serving everyone else.
                    with contextlib.suppress(OSError):
                        await sock.sendto(reply, addr[0], addr[1])

            tg.start_soon(_one)


async def _tcp_connection(stream: anyio.abc.SocketStream, state: DnsState) -> None:
    async def recv_exact(count: int) -> bytes | None:
        buf = b""
        while len(buf) < count:
            try:
                chunk = await stream.receive(count - len(buf))
            except anyio.EndOfStream:
                return None
            buf += chunk
        return buf

    async with stream:
        while True:
            header = await recv_exact(2)
            if header is None:
                return
            body = await recv_exact(int.from_bytes(header, "big"))
            if body is None:
                return
            try:
                reply = await handle_wire(body, state, use_tcp=True)
            except ValueError:
                return
            await stream.send(len(reply).to_bytes(2, "big") + reply)


async def serve_tcp_listener(
    listener: anyio.abc.MultiListener[anyio.abc.SocketStream], state: DnsState
) -> None:
    await listener.serve(lambda stream: _tcp_connection(stream, state))


async def _serve_address(
    host: str,
    port: int,
    state: DnsState,
    report: bool,
    *,
    task_status: anyio.abc.TaskStatus[anyio.CancelScope | None] = (
        anyio.TASK_STATUS_IGNORED
    ),
) -> None:
    """Serve one address until cancelled through the scope it starts with.

    Starts with None when neither protocol binds.
    """
    try:
        udp: anyio.abc.UDPSocket | None = await anyio.create_udp_socket(
            local_host=host, local_port=port
        )
    except OSError as exc:
        udp = None
        if report:
            print(_bind_hint(host, port, "UDP", exc), file=sys.stderr)
    try:
        tcp: anyio.abc.MultiListener[anyio.abc.SocketStream] | None = (
            await anyio.create_tcp_listener(local_host=host, local_port=port)
        )
    except OSError as exc:
        tcp = None
        if report:
            print(_bind_hint(host, port, "TCP", exc), file=sys.stderr)
    if udp is None and tcp is None:
        task_status.started(None)
        return
    # serve_tcp_listener leaves closing to its caller; an address that goes
    # away must free its port for the next bridge that takes it.
    async with contextlib.AsyncExitStack() as stack, anyio.create_task_group() as tg:
        if tcp is not None:
            await stack.enter_async_context(tcp)
        if udp is not None:
            tg.start_soon(serve_udp_sock, udp, state)
        if tcp is not None:
            tg.start_soon(serve_tcp_listener, tcp, state)
        task_status.started(tg.cancel_scope)


async def serve_interfaces(
    listen: tuple[tuple[str, int], ...],
    state: DnsState,
    interval: float,
    read: Callable[[], Mapping[str, Iterable[str]]] = (
        interfaces_mod.read_interface_addresses
    ),
) -> None:
    """Follow the addresses of matching interfaces, binding as they come and go.

    A VM bridge exists only while a VM runs, so a fixed listen list cannot
    name its address.
    """
    serving: dict[tuple[str, int], anyio.CancelScope] = {}
    failed: set[tuple[str, int]] = set()
    async with anyio.create_task_group() as tg:
        while True:
            try:
                entries = await anyio.to_thread.run_sync(read)
            except Exception:  # noqa: BLE001 - next tick retries
                entries = None
            if entries is not None:
                wanted = {
                    (host, port)
                    for pattern, port in listen
                    for host in interfaces_mod.select_addresses(entries, [pattern])
                }
                for key in serving.keys() - wanted:
                    serving.pop(key).cancel()
                failed &= wanted
                for key in wanted - serving.keys():
                    host, port = key
                    scope = await tg.start(
                        _serve_address, host, port, state, key not in failed
                    )
                    if scope is None:
                        failed.add(key)
                    else:
                        serving[key] = scope
                        failed.discard(key)
            await anyio.sleep(interval)


async def refresh_loop(
    state: DnsState, self_hosts: set[str], timeout: float, config_path: str
) -> None:
    prev: store_mod.Snapshot | None = None
    async for snap in store_mod.watch(timeout, self_hosts, config_path):
        state.replace(snap)
        if state.route_filter == routes_mod.RouteFilter.OFF:
            continue
        if state.routes.stale() or snap != prev:
            state.routes = await anyio.to_thread.run_sync(
                routes_mod.read_system_routes
            )
        prev = snap


async def run(
    settings: DaemonSettings,
    config_path: str = DEFAULT_CONFIG_PATH,
    lifecycle: control_mod.Lifecycle | None = None,
) -> None:
    state = DnsState(route_filter=settings.server.route_filter)
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
        # One shared DoH client for the daemon's lifetime: connection
        # pooling instead of a handshake per query. http2=True because
        # Quad9 answers HTTP/1.1 DoH with 505 and requires HTTP/2 per
        # RFC 8484 section 5.2; servers without ALPN fall back to 1.1.
        state.doh_client = await stack.enter_async_context(
            httpx.AsyncClient(http2=True)
        )
        async with anyio.create_task_group() as tg:
            for sock in udp_socks:
                tg.start_soon(serve_udp_sock, sock, state)
            for listener in tcp_listeners:
                tg.start_soon(serve_tcp_listener, listener, state)
            tg.start_soon(
                refresh_loop, state, self_hosts, settings.server.timeout, config_path
            )
            if settings.server.listen_interfaces:
                tg.start_soon(
                    serve_interfaces,
                    settings.server.listen_interfaces,
                    state,
                    settings.server.interval,
                )
            tg.start_soon(
                serve_control_guarded,
                settings.server.control_socket,
                state.cache,
                settings.server.control_socket_group,
                state.latency,
                lifecycle,
            )


async def serve_control_guarded(
    path: str,
    cache: cache_mod.DnsCache,
    group: str | None,
    stats: latency_mod.LatencyStats | None,
    lifecycle: control_mod.Lifecycle | None,
) -> None:
    try:
        await control_mod.serve_control(path, cache, group, stats, lifecycle)
    except OSError as exc:
        print(f"pymacdns: control socket {path}: {exc}", file=sys.stderr)


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
