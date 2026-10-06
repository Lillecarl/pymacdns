from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

import dns.message
import dns.rcode
import dns.rdatatype

CLIENT_TTL_CAP: Final = 10
STALE_MAX_AGE_DAYS: Final = 14
MAX_ENTRIES: Final = 8192


@dataclass(frozen=True)
class CacheKey:
    name: str
    qtype: int
    qclass: int


def make_key(qname: str, qtype: int, qclass: int) -> CacheKey:
    name = qname.lower()
    if not name.endswith("."):
        name += "."
    return CacheKey(name=name, qtype=qtype, qclass=qclass)


def key_of(wire: bytes) -> CacheKey:
    request = dns.message.from_wire(wire)
    if not request.question:
        raise ValueError("DNS message has no question")
    question = request.question[0]
    return make_key(str(question.name), question.rdtype, question.rdclass)


def effective_ttl(response: dns.message.Message) -> int:
    """Minimum answer TTL, else the negative-caching TTL from the SOA."""
    if response.answer:
        return min(rrset.ttl for rrset in response.answer)
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.SOA:
            for rdata in rrset:
                return min(rrset.ttl, rdata.minimum)
    return 0


def cap_ttls(wire: bytes, cap: int = CLIENT_TTL_CAP) -> bytes:
    """Rewrite every record TTL to min(ttl, cap). Pure function."""
    try:
        message = dns.message.from_wire(wire)
    except Exception:
        return wire
    for section in (message.answer, message.authority, message.additional):
        for rrset in section:
            if rrset.ttl > cap:
                rrset.ttl = cap
    return message.to_wire()


@dataclass
class Entry:
    key: CacheKey
    wire: bytes
    fetched_at: float
    min_ttl: int
    records: int

    def dead(self, now: float) -> bool:
        return now > self.fetched_at + self.min_ttl

    def expired(self, now: float, max_age_days: float = STALE_MAX_AGE_DAYS) -> bool:
        return now > self.fetched_at + max_age_days * 86400


@dataclass
class DnsCache:
    max_entries: int = MAX_ENTRIES
    clock: Callable[[], float] = time.monotonic
    _entries: OrderedDict[CacheKey, Entry] = field(default_factory=OrderedDict)

    def get(self, key: CacheKey) -> Entry | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        self._entries.move_to_end(key)
        return entry

    def store(self, key: CacheKey, wire: bytes) -> None:
        try:
            response = dns.message.from_wire(wire)
        except Exception:
            return
        if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return
        now = self.clock()
        self.purge(now)
        self._entries[key] = Entry(
            key=key,
            wire=wire,
            fetched_at=now,
            min_ttl=effective_ttl(response),
            records=sum(len(rrset) for rrset in response.answer),
        )
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def purge(self, now: float | None = None) -> int:
        moment = now if now is not None else self.clock()
        dead_keys = [
            key for key, entry in self._entries.items() if entry.expired(moment)
        ]
        for key in dead_keys:
            del self._entries[key]
        return len(dead_keys)

    def remove(self, name: str, qtype: int | None = None) -> int:
        key = make_key(name, 0, 0)
        gone = 0
        for stored in [k for k in self._entries if k.name == key.name]:
            if qtype is None or stored.qtype == qtype:
                del self._entries[stored]
                gone += 1
        return gone

    def clear(self) -> int:
        count = len(self._entries)
        self._entries.clear()
        return count

    def describe(self) -> list[dict[str, object]]:
        now = self.clock()
        return [
            {
                "name": entry.key.name,
                "qtype": dns.rdatatype.to_text(entry.key.qtype),
                "age_s": round(now - entry.fetched_at, 1),
                "ttl_left_s": round(entry.fetched_at + entry.min_ttl - now, 1),
                "dead": entry.dead(now),
                "records": entry.records,
            }
            for entry in self._entries.values()
        ]
