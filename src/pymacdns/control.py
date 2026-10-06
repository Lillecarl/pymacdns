from __future__ import annotations

import json
from pathlib import Path
from typing import Final

import anyio
import dns.rdatatype

from pymacdns import cache as cache_mod

MAX_REQUEST_BYTES: Final = 65536


async def handle_connection(
    stream: anyio.abc.SocketStream, cache: cache_mod.DnsCache
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
        try:
            request = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            await stream.send(b'{"error": "bad request"}\n')
            return
        payload = (json.dumps(dispatch(cache, request)) + "\n").encode()
        await stream.send(payload)


def dispatch(
    cache: cache_mod.DnsCache, request: object
) -> dict[str, object]:
    if not isinstance(request, dict):
        return {"error": "bad request"}
    op = request.get("op")
    if op == "list":
        return {"entries": cache.describe()}
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


async def serve_control(path: str, cache: cache_mod.DnsCache) -> None:
    target = Path(path)
    try:
        target.unlink(missing_ok=True)
    except OSError:
        pass
    listener = await anyio.create_unix_listener(str(target))
    try:
        target.chmod(0o600)
    except OSError:
        pass
    await listener.serve(lambda stream: handle_connection(stream, cache))


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
