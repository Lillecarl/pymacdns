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
        ("default", "tls://9.9.9.9"),
        ("default", "9.9.9.9"),
        ("dynami.st.", "10.0.250.1"),
        ("example.com.", "tls://9.9.9.9"),
    ]


def test_render_aligns_cells():
    rows = [("default", "tls://9.9.9.9"), ("default", "9.9.9.9")]
    probes = (("example.com.", "A"), ("example.com.", "AAAA"))
    results = {
        ("tls://9.9.9.9", ("example.com.", "A")): 41.2,
        ("tls://9.9.9.9", ("example.com.", "AAAA")): "SERVFAIL",
        ("9.9.9.9", ("example.com.", "A")): "timeout",
    }
    text = status_mod.render(rows, results, probes)
    lines = text.splitlines()
    assert lines[0].split() == ["UPSTREAM", "SCOPE", "A", "AAAA"]
    assert "41ms" in lines[1] and "SERVFAIL" in lines[1]
    assert "timeout" in lines[2] and lines[2].rstrip().endswith("-")
    assert lines[1].index("default") == lines[2].index("default") > 0


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
    probes = (("example.com.", "A"), ("example.com.", "AAAA"))
    nameservers = [
        f"127.0.0.1:{plain_port}",
        f"tls://127.0.0.1:{tls_port}",
        "tls://127.0.0.1:9",
        "gopher://127.0.0.1",
    ]
    async with plain_listener, udp_sock:
        async with anyio.create_task_group() as tg:
            tg.start_soon(tls_listener.serve, answer_tls)
            tg.start_soon(answer_plain_udp, udp_sock)
            await anyio.sleep(0.2)
            results = await status_mod.check(
                nameservers, 2.0, probes, ssl_context=client_ctx
            )
            tg.cancel_scope.cancel()
    for ns in nameservers[:2]:
        for probe in probes:
            assert isinstance(results[(ns, probe)], float), (ns, probe)
    refused = results[("tls://127.0.0.1:9", ("example.com.", "A"))]
    assert refused in ("conn", "timeout"), refused
    assert results[("gopher://127.0.0.1", ("example.com.", "A"))] == "bad"


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

    async def fake_check(nameservers: list[str], timeout: float) -> dict:
        seen["nameservers"] = nameservers
        seen["timeout"] = timeout
        return {}

    def fake_snapshot(timeout: float, self_hosts: set[str], path: str):
        seen["self_hosts"] = self_hosts
        return store_mod.Snapshot(
            standard=resolver_mod.Upstream(["9.9.9.9"], timeout)
        )

    monkeypatch.setattr(store_mod, "snapshot_once", fake_snapshot)
    monkeypatch.setattr(status_mod, "check", fake_check)
    monkeypatch.setattr(
        status_mod, "render", lambda rows, results: f"{len(rows)} rows"
    )
    code = anyio.run(main_mod.status_main, args)
    assert code == 0
    assert seen["timeout"] == 2.0
    assert seen["nameservers"] == ["9.9.9.9"]
    assert seen["self_hosts"] == {"127.0.0.1"}
