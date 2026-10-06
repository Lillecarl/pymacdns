"""Latency buckets: placement, quantiles, recording, and display."""

import anyio
import dns.message
import dns.rcode
import pytest
from helpers import answer_plain_udp

from pymacdns import latency as latency_mod
from pymacdns import resolver as resolver_mod


def test_observe_fills_cumulative_buckets():
    histogram = latency_mod.Histogram()
    histogram.observe(0.003)
    assert histogram.buckets[0] == 0
    assert histogram.buckets[1] == 0
    assert histogram.buckets[2] == 1
    assert histogram.buckets[-1] == 1
    assert histogram.count == 1


def test_quantiles_and_mean():
    stats = latency_mod.LatencyStats()
    for _ in range(100):
        stats.record_ok("tls://9.9.9.9", 0.040)
    row = stats.summary()["tls://9.9.9.9"]
    assert row["count"] == 100
    assert row["errors"] == 0
    assert row["mean_ms"] == pytest.approx(40.0)
    assert row["p50_ms"] == 50.0
    assert row["p95_ms"] == 50.0
    assert row["p99_ms"] == 50.0


def test_tail_quantile_sees_outliers():
    stats = latency_mod.LatencyStats()
    for _ in range(9):
        stats.record_ok("tls://9.9.9.9", 0.005)
    stats.record_ok("tls://9.9.9.9", 0.500)
    row = stats.summary()["tls://9.9.9.9"]
    assert row["p50_ms"] == 5.0
    assert row["p95_ms"] == 500.0


def test_errors_counted_apart():
    stats = latency_mod.LatencyStats()
    stats.record_ok("tls://9.9.9.9", 0.040)
    stats.record_err("tls://9.9.9.9")
    stats.record_err("tls://9.9.9.9")
    row = stats.summary()["tls://9.9.9.9"]
    assert row["count"] == 1
    assert row["errors"] == 2


def test_empty_histogram_is_zero():
    row = latency_mod.LatencyStats().summary()
    assert row == {}
    assert latency_mod.Histogram().quantile(0.99) == 0.0
    assert latency_mod.Histogram().mean() == 0.0


def test_beyond_last_bucket_is_infinite():
    stats = latency_mod.LatencyStats()
    stats.record_ok("tls://9.9.9.9", 60.0)
    assert stats.summary()["tls://9.9.9.9"]["p99_ms"] == float("inf")
    assert "+Inf" in latency_mod.format_table(stats.summary())


def test_format_table_aligns():
    stats = latency_mod.LatencyStats()
    stats.record_ok("tls://9.9.9.9", 0.040)
    stats.record_err("9.9.9.9")
    lines = latency_mod.format_table(stats.summary()).splitlines()
    assert lines[0].split() == ["UPSTREAM", "COUNT", "ERR", "MEAN", "P50", "P95", "P99"]
    assert "40ms" in lines[2]
    padded = "9.9.9.9".ljust(len("tls://9.9.9.9"))
    assert lines[1][: len(padded)] == padded


@pytest.mark.anyio
async def test_lookup_records_winner_and_errors():
    port = 18562
    udp_sock = await anyio.create_udp_socket(
        local_host="127.0.0.1", local_port=port
    )
    wire = dns.message.make_query("example.com.", "A").to_wire()
    stats = latency_mod.LatencyStats()
    bad = "127.0.0.1:9"
    good = f"127.0.0.1:{port}"
    async with udp_sock:
        async with anyio.create_task_group() as tg:
            tg.start_soon(answer_plain_udp, udp_sock)
            await anyio.sleep(0.2)
            upstream = resolver_mod.Upstream([bad, good], timeout=2.0)
            reply = await resolver_mod.lookup(wire, upstream, stats=stats)
            assert dns.message.from_wire(reply).rcode() == dns.rcode.NOERROR
            tg.cancel_scope.cancel()
    summary = stats.summary()
    assert summary[bad]["errors"] == 1
    assert summary[bad]["count"] == 0
    assert summary[good]["count"] == 1
    assert summary[good]["errors"] == 0


@pytest.mark.anyio
async def test_lookup_records_nothing_unobserved():
    port = 18563
    udp_sock = await anyio.create_udp_socket(
        local_host="127.0.0.1", local_port=port
    )
    wire = dns.message.make_query("example.com.", "A").to_wire()
    stats = latency_mod.LatencyStats()
    good = f"127.0.0.1:{port}"
    async with udp_sock:
        async with anyio.create_task_group() as tg:
            tg.start_soon(answer_plain_udp, udp_sock)
            await anyio.sleep(0.2)
            upstream = resolver_mod.Upstream([good, "127.0.0.1:9"], timeout=2.0)
            await resolver_mod.lookup(wire, upstream, stats=stats)
            tg.cancel_scope.cancel()
    assert list(stats.summary()) == [good]


@pytest.mark.anyio
async def test_handle_wire_records_upstream_latency():
    from pymacdns import server as server_mod

    port = 18564
    udp_sock = await anyio.create_udp_socket(
        local_host="127.0.0.1", local_port=port
    )
    state = server_mod.DnsState()
    state.standard = resolver_mod.Upstream([f"127.0.0.1:{port}"], timeout=2.0)
    wire = dns.message.make_query("example.com.", "A").to_wire()
    async with udp_sock:
        async with anyio.create_task_group() as tg:
            tg.start_soon(answer_plain_udp, udp_sock)
            await anyio.sleep(0.2)
            out = dns.message.from_wire(await server_mod.handle_wire(wire, state, False))
            assert out.rcode() == dns.rcode.NOERROR
            tg.cancel_scope.cancel()
    row = state.latency.summary()[f"127.0.0.1:{port}"]
    assert row["count"] == 1


def test_dispatch_latency_op():
    from pymacdns import control as control_mod

    cache = control_mod.cache_mod.DnsCache()
    assert control_mod.dispatch(cache, {"op": "latency"}) == {"latency": {}}
    stats = latency_mod.LatencyStats()
    stats.record_ok("tls://9.9.9.9", 0.040)
    reply = control_mod.dispatch(cache, {"op": "latency"}, stats)
    assert reply["latency"]["tls://9.9.9.9"]["count"] == 1
