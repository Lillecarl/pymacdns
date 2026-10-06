"""Route table parsing, coverage checks, and response filtering."""

import ipaddress

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

from pymacdns.routes import (
    RouteFilter,
    RouteTable,
    filter_response,
    has_default_route,
    parse_netstat,
)

V6_TABLE = """Routing tables

Internet6:
Destination Gateway Flags Netif Expire
default fe80::%utun4 UGcIg utun4
::1 ::1 UHL lo0
2a01:4f9:3071:11d7::/64 link#23 UCS utun4
fe80::%utun4/64 fe80::a92:4ff:fec4:4163%utun4 Uc utun4
"""

V4_TABLE = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.247.250.1       UGScg                 en0
10.247.250/24      link#15            UCS                   en0
127.0.0.1          127.0.0.1          UH                    lo0
"""


def lab_table(*, default_v6: bool = True) -> RouteTable:
    nets = parse_netstat(V6_TABLE) + parse_netstat(V4_TABLE)
    if default_v6 and has_default_route(V6_TABLE):
        nets.append(ipaddress.ip_network("::/0"))
    if has_default_route(V4_TABLE):
        nets.append(ipaddress.ip_network("0.0.0.0/0"))
    return RouteTable(nets=tuple(nets))


def test_parse_netstat_v6():
    nets = {str(n) for n in parse_netstat(V6_TABLE)}
    assert "2a01:4f9:3071:11d7::/64" in nets
    assert "fe80::/64" in nets
    assert "::1/128" in nets
    assert has_default_route(V6_TABLE)
    assert not has_default_route("Destination Gateway\n10.0.0/24 link#1\n")


def test_covers_lab_prefix():
    table = lab_table()
    assert table.covers("2a01:4f9:3071:11d7:e2::1")
    assert table.covers("93.184.216.34")
    assert table.family_usable(6)
    assert table.family_usable(4)


def test_family_mode_drops_unusable_family():
    v4_only = RouteTable(
        nets=tuple(n for n in lab_table().nets if n.version == 4)
    )
    assert v4_only.family_usable(4)
    assert not v4_only.family_usable(6)


def answer_wire() -> bytes:
    q = dns.message.make_query("svc.lab.", "AAAA")
    resp = dns.message.make_response(q)
    for addr in ("2a01:4f9:3071:11d7:e2::1", "2001:db8::dead"):
        resp.answer.append(dns.rrset.from_text("svc.lab.", 60, "IN", "AAAA", addr))
    return resp.to_wire()


def test_prefix_mode_prunes_unrouted():
    # No v6 default here: the lab /64 stays, documentation space goes.
    table = lab_table(default_v6=False)
    assert table.family_usable(6)
    out = dns.message.from_wire(
        filter_response(answer_wire(), table, RouteFilter.PREFIX)
    )
    addrs = [r.address for rrset in out.answer for r in rrset]
    assert addrs == ["2a01:4f9:3071:11d7:e2::1"]


def test_off_is_transparent():
    wire = answer_wire()
    assert filter_response(wire, lab_table(), RouteFilter.OFF) == wire


def test_fail_open_when_everything_filtered():
    empty = RouteTable(nets=())
    wire = answer_wire()
    assert filter_response(wire, empty, RouteFilter.PREFIX) == wire
    assert filter_response(wire, empty, RouteFilter.FAMILY) == wire


def test_non_answer_kinds_untouched():
    q = dns.message.make_query("svc.lab.", "MX")
    resp = dns.message.make_response(q)
    resp.answer.append(
        dns.rrset.from_text("svc.lab.", 60, "IN", "MX", "10 mail.svc.lab.")
    )
    assert (
        filter_response(resp.to_wire(), RouteTable(nets=()), RouteFilter.PREFIX)
        == resp.to_wire()
    )
    q2 = dns.message.make_query("missing.lab.", "A")
    missing = dns.message.make_response(q2)
    missing.set_rcode(dns.rcode.NXDOMAIN)
    assert (
        filter_response(missing.to_wire(), RouteTable(nets=()), RouteFilter.PREFIX)
        == missing.to_wire()
    )
