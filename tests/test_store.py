"""Store discovery against Apple-documented shapes.

Fixtures model the DNS dictionary from Apple's device management schema
(ServerAddresses, SearchDomains, DomainName, SupplementalMatchDomains,
SupplementalMatchOrders) as written by real VPN clients (ZeroTier's
MacDNSHelper writes match domains plus search domains with no orders;
NetBird fans out across several State:/Network/Service/*/DNS keys).
"""

from pymacdns import resolver as resolver_mod
from pymacdns.store import (
    STORE_RANK,
    TOML_RANK,
    Candidate,
    ServiceDns,
    file_candidates,
    merge_to_snapshot,
    system_candidates,
)

HOSTS: set[str] = set()


def test_plain_dhcp_global_only():
    cands = system_candidates(["10.247.250.1"], [], HOSTS)
    snap = merge_to_snapshot(cands, 2.0)
    assert snap.standard is not None
    assert snap.standard.nameservers == ["10.247.250.1"]
    assert snap.domains == {}


def test_zerotier_style_split_dns():
    """Split tunnel: corp names to VPN DNS, rest to the default."""
    cands = system_candidates(
        ["10.247.250.1"],
        [
            ServiceDns(
                servers=("10.0.1.1",),
                match_domains=("corp.example",),
            )
        ],
        HOSTS,
    )
    snap = merge_to_snapshot(cands, 2.0)
    assert snap.domains["corp.example"].nameservers == ["10.0.1.1"]
    assert resolver_mod.pick_upstream(
        "db.corp.example.", snap.domains, snap.standard
    ).nameservers == ["10.0.1.1"]
    assert resolver_mod.pick_upstream(
        "example.com.", snap.domains, snap.standard
    ).nameservers == ["10.247.250.1"]


def test_empty_match_domain_becomes_default_first():
    """Apple: empty SupplementalMatchDomains directs all queries to VPN first."""
    cands = system_candidates(
        ["10.247.250.1"],
        [
            ServiceDns(
                servers=("10.0.1.1",),
                match_domains=("",),
                match_orders=("100600",),
            )
        ],
        HOSTS,
    )
    snap = merge_to_snapshot(cands, 2.0)
    assert snap.standard is not None
    assert snap.standard.nameservers == ["10.0.1.1", "10.247.250.1"]


def test_netbird_style_batched_keys_concatenate():
    """Several service keys for one product merge into one domain."""
    cands = system_candidates(
        ["10.247.250.1"],
        [
            ServiceDns(servers=("100.64.0.1",), match_domains=("a.mesh",)),
            ServiceDns(servers=("100.64.0.1",), match_domains=("b.mesh",)),
        ],
        HOSTS,
    )
    snap = merge_to_snapshot(cands, 2.0)
    assert snap.domains["a.mesh"].nameservers == ["100.64.0.1"]
    assert snap.domains["b.mesh"].nameservers == ["100.64.0.1"]


def test_explicit_orders_win_over_defaults():
    cands = system_candidates(
        ["10.247.250.1"],
        [
            ServiceDns(
                servers=("10.0.2.2",),
                match_domains=("corp.example",),
                match_orders=("50000",),
            )
        ],
        HOSTS,
    ) + [
        Candidate(
            domain="corp.example",
            nameservers=("10.0.1.1",),
            priority=100000,
            source_rank=STORE_RANK,
        )
    ]
    snap = merge_to_snapshot(cands, 2.0)
    assert snap.domains["corp.example"].nameservers == ["10.0.2.2", "10.0.1.1"]


def test_toml_negative_priority_beats_everything():
    cands = system_candidates(["10.247.250.1"], [], HOSTS) + [
        Candidate(
            domain="",
            nameservers=("9.9.9.9",),
            priority=-100,
            source_rank=TOML_RANK,
        )
    ]
    snap = merge_to_snapshot(cands, 2.0)
    assert snap.standard is not None
    assert snap.standard.nameservers == ["9.9.9.9", "10.247.250.1"]


def test_resolver_files_feed_domains():
    cands = file_candidates(
        {"dynami.st": "nameserver 10.0.250.1\n", ".hidden": "nameserver 1.1.1.1\n"},
        HOSTS,
    )
    snap = merge_to_snapshot(
        cands
        + system_candidates(["10.247.250.1"], [], HOSTS),
        2.0,
    )
    assert snap.domains["dynami.st"].nameservers == ["10.0.250.1"]
    assert ".hidden" not in snap.domains


def test_self_addresses_filtered():
    cands = system_candidates(
        ["127.0.0.1", "10.247.250.1"], [], {"127.0.0.1"}
    )
    snap = merge_to_snapshot(cands, 2.0)
    assert snap.standard is not None
    assert snap.standard.nameservers == ["10.247.250.1"]


def test_no_upstreams_is_none_not_fallback():
    snap = merge_to_snapshot(system_candidates([], [], HOSTS), 2.0)
    assert snap.standard is None
    assert snap.domains == {}
