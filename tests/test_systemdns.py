"""SystemDns dictionary: what mDNSResponder is told while we run."""

import pytest

from pymacdns.installer import (
    SYSTEM_DNS_ORDER,
    SYSTEM_RESOLV_CONF,
    FileMarker,
    ResolvConf,
    SystemDns,
    nuke_targets,
    system_dns_dict,
)


def test_nuke_covers_system_settings_without_config():
    targets = nuke_targets([])
    assert [type(t) for t in targets] == [SystemDns, ResolvConf]
    assert targets[1].path == SYSTEM_RESOLV_CONF


def test_nuke_keeps_configured_and_dedupes(tmp_path):
    marker = FileMarker(str(tmp_path / "marker"))
    custom = ResolvConf(str(tmp_path / "resolv.conf"), ["127.0.0.1"])
    targets = nuke_targets(
        [marker, custom, ResolvConf(SYSTEM_RESOLV_CONF, ["127.0.0.1"])]
    )
    assert targets[:2] == [marker, custom]
    assert sum(isinstance(t, SystemDns) for t in targets) == 1
    assert sum(
        isinstance(t, ResolvConf) and t.path == SYSTEM_RESOLV_CONF for t in targets
    ) == 1


def test_dict_routes_everything_to_listeners():
    assert system_dns_dict([("127.0.0.1", 53), ("::1", 53)]) == {
        "ServerAddresses": ["127.0.0.1", "::1"],
        "SupplementalMatchDomains": [""],
        "SupplementalMatchOrders": [SYSTEM_DNS_ORDER],
    }


def test_dict_carries_nonstandard_port():
    assert system_dns_dict([("127.0.0.1", 5353)])["ServerPort"] == 5353


def test_dict_rejects_mixed_ports():
    with pytest.raises(ValueError, match="one listen port"):
        system_dns_dict([("127.0.0.1", 53), ("::1", 5353)])
