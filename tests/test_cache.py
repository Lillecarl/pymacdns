"""Stale-while-error cache: TTL cap, death, fallback, and surgery."""

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from pymacdns import cache as cache_mod
from pymacdns import resolver as resolver_mod


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def answer_wire(name="svc.lab.", ttl=300) -> bytes:
    q = dns.message.make_query(name, "AAAA")
    resp = dns.message.make_response(q)
    resp.answer.append(dns.rrset.from_text(name, ttl, "IN", "AAAA", "2a01:db8::1"))
    return resp.to_wire()


def test_cap_ttls():
    out = dns.message.from_wire(cache_mod.cap_ttls(answer_wire(ttl=3600)))
    assert [rrset.ttl for rrset in out.answer] == [10]
    out2 = dns.message.from_wire(cache_mod.cap_ttls(answer_wire(ttl=5)))
    assert [rrset.ttl for rrset in out2.answer] == [5]


def test_store_get_and_death():
    clock = Clock()
    cache = cache_mod.DnsCache(clock=clock)
    key = cache_mod.make_key("svc.lab.", dns.rdatatype.AAAA, 1)
    assert cache.get(key) is None
    cache.store(key, answer_wire(ttl=300))
    assert cache.get(key) is not None
    clock.now += 299
    assert not cache.get(key).dead(clock.now)
    clock.now += 2
    assert cache.get(key).dead(clock.now)


def test_no_cache_servfail_and_negatives():
    clock = Clock()
    cache = cache_mod.DnsCache(clock=clock)
    key = cache_mod.make_key("svc.lab.", dns.rdatatype.A, 1)
    q = dns.message.make_query("svc.lab.", "A")
    fail = dns.message.make_response(q)
    fail.set_rcode(dns.rcode.SERVFAIL)
    cache.store(key, fail.to_wire())
    assert cache.get(key) is None
    missing = dns.message.make_response(
        dns.message.make_query("gone.lab.", "A")
    )
    missing.set_rcode(dns.rcode.NXDOMAIN)
    key2 = cache_mod.make_key("gone.lab.", dns.rdatatype.A, 1)
    cache.store(key2, missing.to_wire())
    assert cache.get(key2) is not None


def test_remove_clear_describe():
    clock = Clock()
    cache = cache_mod.DnsCache(clock=clock)
    cache.store(cache_mod.make_key("a.lab.", 1, 1), answer_wire("a.lab."))
    cache.store(cache_mod.make_key("b.lab.", 28, 1), answer_wire("b.lab."))
    assert cache.remove("a.lab.") == 1
    assert cache.remove("b.lab.", qtype=1) == 0
    assert cache.remove("b.lab.", qtype=28) == 1
    described = cache.describe()
    assert described == []
    cache.store(cache_mod.make_key("c.lab.", 28, 1), answer_wire("c.lab."))
    assert cache.clear() == 1


@pytest.mark.anyio
async def test_stale_served_on_upstream_failure():
    from pymacdns import server as server_mod

    clock = Clock()
    state = server_mod.DnsState()
    state.cache = cache_mod.DnsCache(clock=clock)
    state.standard = resolver_mod.Upstream(
        nameservers=["127.0.0.1:1"], timeout=0.2
    )
    wire = dns.message.make_query("svc.lab.", "AAAA").to_wire()
    key = cache_mod.key_of(wire)
    state.cache.store(key, answer_wire(ttl=300))
    clock.now += 500
    out = dns.message.from_wire(await server_mod.handle_wire(wire, state, False))
    assert dns.rcode.to_text(out.rcode()) == "NOERROR"
    assert [r.address for rrset in out.answer for r in rrset] == ["2a01:db8::1"]
    assert [rrset.ttl for rrset in out.answer] == [10]


@pytest.mark.anyio
async def test_fresh_cache_needs_no_upstream():
    from pymacdns import server as server_mod

    state = server_mod.DnsState()
    state.cache = cache_mod.DnsCache(clock=Clock())
    state.standard = resolver_mod.Upstream(
        nameservers=["127.0.0.1:1"], timeout=0.2
    )
    wire = dns.message.make_query("svc.lab.", "AAAA").to_wire()
    state.cache.store(cache_mod.key_of(wire), answer_wire(ttl=300))
    out = dns.message.from_wire(await server_mod.handle_wire(wire, state, False))
    assert [r.address for rrset in out.answer for r in rrset] == ["2a01:db8::1"]
