from __future__ import annotations

import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Final

import anyio
from anyio.from_thread import BlockingPortal

from pymacdns import resolver as resolver_mod

GLOBAL_DNS_KEY: Final = "State:/Network/Global/DNS"
SERVICE_NOTIFY_PATTERNS: Final = [
    r"State:/Network/Service/.*",
    r"Setup:/Network/Service/.*",
]
RUNLOOP_TICK: Final = 1.0
STREAM_BUFFER: Final = 8


@dataclass
class Snapshot:
    # Split-domain routing stays empty until pymacdns owns that config.
    standard: resolver_mod.Upstream | None = None
    domains: dict[str, resolver_mod.Upstream] = field(default_factory=dict)


def _str_list(value: object) -> list[str]:
    if value is None:
        return []
    return [str(item) for item in list(value)]  # type: ignore[arg-type]


def _read_snapshot(self_hosts: set[str], timeout: float) -> Snapshot:
    """Read the system default DNS servers from the dynamic store.

    Runs in a worker thread; PyObjC imports stay here so the event
    loop never pays the import cost.
    """
    from SystemConfiguration import SCDynamicStoreCopyValue, SCDynamicStoreCreate

    store = SCDynamicStoreCreate(None, "pymacdns", None, None)
    global_info = dict(SCDynamicStoreCopyValue(store, GLOBAL_DNS_KEY) or {})
    addrs = [
        addr
        for addr in _str_list(global_info.get("ServerAddresses"))
        if addr not in self_hosts
    ]
    return Snapshot(
        standard=resolver_mod.Upstream(nameservers=addrs, timeout=timeout)
        if addrs
        else None,
    )


def _run_watcher(
    portal: BlockingPortal,
    send: anyio.abc.MemoryObjectSendStream[Snapshot],
    self_hosts: set[str],
    timeout: float,
    stop: threading.Event,
) -> None:
    from CoreFoundation import (
        CFRunLoopAddSource,
        CFRunLoopGetCurrent,
        CFRunLoopRunInMode,
        kCFRunLoopDefaultMode,
    )
    from SystemConfiguration import (
        SCDynamicStoreCreate,
        SCDynamicStoreCreateRunLoopSource,
        SCDynamicStoreSetNotificationKeys,
    )

    store = SCDynamicStoreCreate(None, "pymacdns-watch", lambda *args: None, None)
    SCDynamicStoreSetNotificationKeys(store, [GLOBAL_DNS_KEY], SERVICE_NOTIFY_PATTERNS)
    source = SCDynamicStoreCreateRunLoopSource(None, store, 0)
    loop = CFRunLoopGetCurrent()
    CFRunLoopAddSource(loop, source, kCFRunLoopDefaultMode)

    last: Snapshot | None = None
    while not stop.is_set():
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, RUNLOOP_TICK, False)
        if stop.is_set():
            break
        try:
            snap = _read_snapshot(self_hosts, timeout)
        except Exception:  # noqa: BLE001 - keep watching, next tick retries
            continue
        if snap != last:
            last = snap
            try:
                portal.call(send.send, snap)
            except RuntimeError:
                return


async def watch(timeout: float, self_hosts: set[str]) -> AsyncIterator[Snapshot]:
    """Yield the current DNS snapshot, then a new one on every change."""
    send, recv = anyio.create_memory_object_stream[Snapshot](
        max_buffer_size=STREAM_BUFFER
    )
    yield await anyio.to_thread.run_sync(_read_snapshot, self_hosts, timeout)

    stop = threading.Event()
    async with BlockingPortal() as portal:
        thread = threading.Thread(
            target=_run_watcher,
            args=(portal, send, self_hosts, timeout, stop),
            daemon=True,
        )
        thread.start()
        try:
            async for snap in recv:
                yield snap
        finally:
            stop.set()
            await anyio.to_thread.run_sync(thread.join, RUNLOOP_TICK + 2.0)
