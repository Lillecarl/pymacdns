"""Reserved-name handling: mDNS namespaces are refused, never forwarded."""

import dns.message
import dns.rcode
import dns.rdatatype

from pymacdns import resolver as resolver_mod


def query_wire(name: str, qtype: str = "A") -> bytes:
    return dns.message.make_query(name, qtype).to_wire()


def rcode_of(wire: bytes) -> str:
    return dns.rcode.to_text(dns.message.from_wire(wire).rcode())


def test_local_refused():
    assert (
        rcode_of(resolver_mod.special_response(query_wire("printer.local.")))
        == "REFUSED"
    )
    assert (
        rcode_of(resolver_mod.special_response(query_wire("x.y.local.", "AAAA")))
        == "REFUSED"
    )


def test_mdns_reverse_zones_refused():
    for name in (
        "b._dns-sd._udp.254.169.in-addr.arpa.",
        "1.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
    ):
        assert (
            rcode_of(resolver_mod.special_response(query_wire(name, "PTR")))
            == "REFUSED"
        )


def test_invalid_nxdomain():
    assert (
        rcode_of(resolver_mod.special_response(query_wire("nope.invalid.")))
        == "NXDOMAIN"
    )
    assert (
        rcode_of(resolver_mod.special_response(query_wire("a.b.invalid.", "AAAA")))
        == "NXDOMAIN"
    )


def test_localhost_loopback():
    answer = dns.message.from_wire(
        resolver_mod.special_response(query_wire("localhost."))
    ).answer
    assert [r.address for rrset in answer for r in rrset] == ["127.0.0.1"]
    answer6 = dns.message.from_wire(
        resolver_mod.special_response(query_wire("localhost.", "AAAA"))
    ).answer
    assert [r.address for rrset in answer6 for r in rrset] == ["::1"]


def test_ordinary_names_forward():
    assert resolver_mod.special_response(query_wire("example.com.")) is None
    assert resolver_mod.special_response(query_wire("host.dynami.st.", "AAAA")) is None
    # VPN supplemental domains are routed, not refused.
    assert resolver_mod.special_response(query_wire("db.corp.example.")) is None
    # Similarly named but outside the namespace still forwards.
    assert resolver_mod.special_response(query_wire("local.example.com.")) is None
    assert resolver_mod.special_response(query_wire("notlocal.")) is None
