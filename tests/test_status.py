"""Upstream status: target listing, table rendering, live probing."""

import anyio
import pytest
from anyio.streams.tls import TLSListener
from helpers import answer_plain_udp, answer_tls, make_contexts

from pymacdns import resolver as resolver_mod
from pymacdns import status as status_mod
from pymacdns import store as store_mod


def test_describe_targets_dedups_and_orders():
    snap = store_mod.Snapshot(
        standard=resolver_mod.Upstream(["tls://9.9.9.9", "9.9.9.9"], 2.0),
        domains={
            "example.com.": resolver_mod.Upstream(["tls://9.9.9.9"], 2.0),
            "dynami.st.": resolver_mod.Upstream(["10.0.250.1"], 2.0),
        },
    )
    assert status_mod.describe_targets(snap) == [
        status_mod.Target("default", "tls://9.9.9.9"),
        status_mod.Target("default", "9.9.9.9"),
        status_mod.Target("dynami.st.", "10.0.250.1"),
        status_mod.Target("example.com.", "tls://9.9.9.9"),
    ]


def test_column_labels_prefix_repeats():
    probes = (
        status_mod.Probe("example.com.", "A"),
        status_mod.Probe("example.com.", "AAAA"),
    )
    assert status_mod.column_labels(probes) == ["A", "AAAA"]
    assert status_mod.column_labels(status_mod.PROBES)[-2:] == [
        "ipv6:AAAA",
        "dnssec-failed:A",
    ]


def test_render_aligns_cells():
    probes = (
        status_mod.Probe("example.com.", "A"),
        status_mod.Probe("example.com.", "AAAA"),
    )
    rows = [
        status_mod.Row(
            status_mod.Target("default", "tls://9.9.9.9"),
            {
                probes[0]: status_mod.Outcome(latency_ms=41.2),
                probes[1]: status_mod.Outcome(rcode="SERVFAIL"),
            },
        ),
        status_mod.Row(
            status_mod.Target("default", "9.9.9.9"),
            {probes[0]: status_mod.Outcome(error="timeout")},
        ),
    ]
    lines = status_mod.render(rows, probes).splitlines()
    assert lines[0].split() == ["UPSTREAM", "SCOPE", "A", "AAAA"]
    assert "41ms" in lines[1] and "SERVFAIL" in lines[1]
    assert "timeout" in lines[2] and lines[2].rstrip().endswith("-")
    padded = "9.9.9.9".ljust(len("tls://9.9.9.9"))
    assert lines[2][: len(padded)] == padded


@pytest.mark.anyio
async def test_check_live_and_unreachable():
    server_ctx, client_ctx = make_contexts()

    tls_port, plain_port = 18560, 18561
    plain_listener = await anyio.create_tcp_listener(
        local_host="127.0.0.1", local_port=tls_port
    )
    tls_listener = TLSListener(plain_listener, server_ctx)
    udp_sock = await anyio.create_udp_socket(
        local_host="127.0.0.1", local_port=plain_port
    )
    probes = (
        status_mod.Probe("example.com.", "A"),
        status_mod.Probe("example.com.", "AAAA"),
    )
    targets = [
        status_mod.Target("default", f"127.0.0.1:{plain_port}"),
        status_mod.Target("default", f"tls://127.0.0.1:{tls_port}"),
        status_mod.Target("default", "tls://127.0.0.1:9"),
        status_mod.Target("default", "gopher://127.0.0.1"),
    ]
    async with plain_listener, udp_sock:
        async with anyio.create_task_group() as tg:
            tg.start_soon(tls_listener.serve, answer_tls)
            tg.start_soon(answer_plain_udp, udp_sock)
            await anyio.sleep(0.2)
            rows = await status_mod.check(
                targets, 2.0, probes, ssl_context=client_ctx
            )
            tg.cancel_scope.cancel()
    assert [row.target for row in rows] == targets
    for row in rows[:2]:
        for probe in probes:
            assert isinstance(row.outcomes[probe].latency_ms, float)
    refused = rows[2].outcomes[probes[0]]
    assert refused.latency_ms is None and refused.error in ("conn", "timeout")
    assert rows[3].outcomes[probes[0]].error == "bad"


@pytest.mark.anyio
async def test_snapshot_once_reads_live_system(tmp_path):
    conf = tmp_path / "pymacdns.toml"
    conf.write_text(
        '[[resolver]]\ndomain = "example.com"\n'
        'nameservers = ["9.9.9.9"]\npriority = -100\n'
    )
    snap = store_mod.snapshot_once(2.0, set(), str(conf))
    assert isinstance(snap, store_mod.Snapshot)
    pinned = snap.domains.get("example.com")
    assert pinned is not None
    assert "9.9.9.9" in pinned.nameservers


def test_status_main_wires_snapshot(monkeypatch, tmp_path):
    import argparse

    from pymacdns import __main__ as main_mod

    conf = tmp_path / "pymacdns.toml"
    conf.write_text('[server]\nlisten = ["127.0.0.1:53"]\n')
    args = argparse.Namespace(
        config=str(conf),
        listen=["127.0.0.1:15561"],
        timeout=None,
        interval=None,
        socket=None,
        marker_file=None,
        resolv_conf=None,
        socket_group=None,
        command="status",
    )
    seen: dict[str, object] = {}

    async def fake_check(targets, timeout, doh_client=None):
        seen["targets"] = targets
        seen["timeout"] = timeout
        seen["client"] = doh_client
        return [status_mod.Row(target, {}) for target in targets]

    def fake_snapshot(timeout: float, self_hosts: set[str], path: str):
        seen["self_hosts"] = self_hosts
        return store_mod.Snapshot(
            standard=resolver_mod.Upstream(["9.9.9.9"], timeout)
        )

    monkeypatch.setattr(store_mod, "snapshot_once", fake_snapshot)
    monkeypatch.setattr(status_mod, "check", fake_check)
    monkeypatch.setattr(
        status_mod, "render", lambda rows: f"{len(rows)} rows"
    )
    code = anyio.run(main_mod.status_main, args)
    assert code == 0
    assert seen["timeout"] == 2.0
    assert seen["targets"] == [status_mod.Target("default", "9.9.9.9")]
    assert seen["self_hosts"] == {"127.0.0.1"}
    assert seen["client"] is not None
