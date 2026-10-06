"""Config parsing and validation."""

import pytest
from pydantic import ValidationError

from pymacdns.config import parse_config


def test_listen_string_and_list():
    assert parse_config('[server]\nlisten = "127.0.0.1:5353"').server.listen == (
        ("127.0.0.1", 5353),
    )
    assert parse_config(
        '[server]\nlisten = ["127.0.0.1:5353", "[::1]:5354"]'
    ).server.listen == (("127.0.0.1", 5353), ("::1", 5354))


def test_route_filter_values():
    assert parse_config("").server.route_filter == "off"
    assert (
        parse_config('[server]\nroute_filter = "prefix"').server.route_filter
        == "prefix"
    )
    with pytest.raises(ValidationError):
        parse_config('[server]\nroute_filter = "sometimes"')


def test_resolver_rules():
    cfg = parse_config(
        '[[resolver]]\ndomain = "Dynami.ST."\n'
        'nameservers = ["10.9.9.9"]\npriority = -5'
    )
    assert cfg.resolver[0].domain == "dynami.st"
    assert cfg.resolver[0].priority == -5


def test_rejections():
    for bad in (
        "[server]\nlisten = []",
        "[[resolver]]\npriority = 1",
        '[[resolver]]\nnameservers = ["1.1.1.1"]\npriority = true',
        "[server]\nbogus = 1",
    ):
        with pytest.raises(ValidationError):
            parse_config(bad)
