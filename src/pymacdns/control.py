from __future__ import annotations

import contextlib
import json
import os
import shutil
from pathlib import Path
from typing import Final, Protocol

import anyio
import dns.rdatatype

from pymacdns import cache as cache_mod
from pymacdns import latency as latency_mod

MAX_REQUEST_BYTES: Final = 65536



class Lifecycle(Protocol):
    """What the daemon installed into macOS, driven over the socket."""

    async def release(self) -> None:
        """Remove the settings and stop restoring them; keep serving."""

    async def restore(self) -> None:
        """Install released settings again; a no-op otherwise."""


LIFECYCLE_OPS: Final = {"release": "released", "restore": "restored"}


async def handle_connection(
    stream: anyio.abc.SocketStream,
    cache: cache_mod.DnsCache,
    stats: latency_mod.LatencyStats | None = None,
    lifecycle: Lifecycle | None = None,
) -> None:
    # The listener runs in the server's task group, so an error escaping
    # here stops DNS too. A client that leaves early is its own problem.
    with contextlib.suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
        await _answer(stream, cache, stats, lifecycle)


async def _answer(
    stream: anyio.abc.SocketStream,
    cache: cache_mod.DnsCache,
    stats: latency_mod.LatencyStats | None,
    lifecycle: Lifecycle | None,
) -> None:
    async with stream:
        data = b""
        while b"\n" not in data:
            try:
                chunk = await stream.receive()
            except anyio.EndOfStream:
                break
            data += chunk
            if len(data) > MAX_REQUEST_BYTES:
                return
        if not data:
            return
        try:
            request = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            await stream.send(b'{"error": "bad request"}\n')
            return
        if isinstance(request, dict) and request.get("op") in LIFECYCLE_OPS:
            reply = await _lifecycle(lifecycle, str(request["op"]))
        else:
            reply = dispatch(cache, request, stats)
        payload = (json.dumps(reply) + "\n").encode()
        await stream.send(payload)


async def _lifecycle(lifecycle: Lifecycle | None, op: str) -> dict[str, object]:
    if lifecycle is None:
        return {"error": f"{op} unsupported"}
    try:
        await getattr(lifecycle, op)()
    except Exception as exc:  # noqa: BLE001 - the caller gets the reason
        return {"error": f"{op} failed: {exc}"}
    return {LIFECYCLE_OPS[op]: True}


def dispatch(
    cache: cache_mod.DnsCache,
    request: object,
    stats: latency_mod.LatencyStats | None = None,
) -> dict[str, object]:
    if not isinstance(request, dict):
        return {"error": "bad request"}
    op = request.get("op")
    if op == "list":
        return {"entries": cache.describe()}
    if op == "pid":
        return {"pid": os.getpid()}
    if op == "latency":
        summaries = stats.summary() if stats is not None else []
        return {
            "latency": {
                summary.nameserver: summary.payload() for summary in summaries
            }
        }
    if op == "clear":
        return {"cleared": cache.clear()}
    if op == "remove":
        name = request.get("name")
        if not isinstance(name, str) or not name:
            return {"error": "remove needs a name"}
        qtype = request.get("qtype", "ANY")
        try:
            qtype_int = (
                None
                if str(qtype).upper() == "ANY"
                else dns.rdatatype.from_text(str(qtype).upper())
            )
        except Exception:
            return {"error": f"unknown qtype {qtype!r}"}
        return {"removed": cache.remove(name, qtype_int)}
    return {"error": f"unknown op {op!r}"}


async def serve_control(
    path: str,
    cache: cache_mod.DnsCache,
    group: str | None = None,
    stats: latency_mod.LatencyStats | None = None,
    lifecycle: Lifecycle | None = None,
) -> None:
    """Serve the control socket, optionally opening it to a group.

    Without a group the socket stays owner-only 0600. With one, the
    socket is chgrp'd and widened to 0770. A failed chown raises: a
    misspelled group or missing privilege must surface at startup,
    not as a silently unreachable socket.
    """
    target = Path(path)
    try:
        target.unlink(missing_ok=True)
    except OSError:
        pass
    listener = await anyio.create_unix_listener(str(target))
    if group is not None:
        shutil.chown(target, group=group)
    try:
        target.chmod(0o770 if group is not None else 0o600)
    except OSError:
        pass
    await listener.serve(
        lambda stream: handle_connection(stream, cache, stats, lifecycle)
    )


async def control_request(path: str, payload: dict[str, object]) -> dict[str, object]:
    stream = await anyio.connect_unix(path)
    async with stream:
        await stream.send((json.dumps(payload) + "\n").encode())
        data = b""
        while True:
            try:
                chunk = await stream.receive()
            except anyio.EndOfStream:
                break
            data += chunk
        return json.loads(data.decode("utf-8"))
