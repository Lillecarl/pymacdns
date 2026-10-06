"""In-memory upstream latency: fixed-bucket histograms, nothing persisted.

One histogram per upstream nameserver: cumulative bucket counters in
the Prometheus style, plus totals and error counts. No timestamps, no
decay: cumulative never forgets, so a past outage stains the high
quantiles until the daemon restarts. That tradeoff is the price of
constant memory; a reset or a sliding window comes later if it bites.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

# Bucket upper bounds in milliseconds. DNS lives left of center;
# the right tail exists so timeouts land somewhere countable.
BOUNDS: Final = (1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 30000)


@dataclass
class Histogram:
    buckets: list[int] = field(default_factory=lambda: [0] * len(BOUNDS))
    count: int = 0
    total_ms: float = 0.0
    errors: int = 0

    def observe(self, seconds: float) -> None:
        ms = seconds * 1000.0
        for i, bound in enumerate(BOUNDS):
            if ms <= bound:
                self.buckets[i] += 1
        self.count += 1
        self.total_ms += ms

    def fail(self) -> None:
        self.errors += 1

    def quantile(self, q: float) -> float:
        """First bucket whose cumulative share reaches q (upper bound)."""
        if self.count == 0:
            return 0.0
        target = q * self.count
        for i, bound in enumerate(BOUNDS):
            if self.buckets[i] >= target:
                return float(bound)
        return float("inf")

    def mean(self) -> float:
        if self.count == 0:
            return 0.0
        return self.total_ms / self.count


@dataclass
class LatencyStats:
    histograms: dict[str, Histogram] = field(default_factory=dict)

    def _histogram(self, nameserver: str) -> Histogram:
        histogram = self.histograms.get(nameserver)
        if histogram is None:
            histogram = Histogram()
            self.histograms[nameserver] = histogram
        return histogram

    def record_ok(self, nameserver: str, seconds: float) -> None:
        self._histogram(nameserver).observe(seconds)

    def record_err(self, nameserver: str) -> None:
        self._histogram(nameserver).fail()

    def summary(self) -> dict[str, dict[str, float]]:
        out = {}
        for ns in sorted(self.histograms):
            histogram = self.histograms[ns]
            out[ns] = {
                "count": float(histogram.count),
                "errors": float(histogram.errors),
                "mean_ms": histogram.mean(),
                "p50_ms": histogram.quantile(0.5),
                "p95_ms": histogram.quantile(0.95),
                "p99_ms": histogram.quantile(0.99),
            }
        return out


def format_table(summary: dict[str, dict[str, float]]) -> str:
    """Align per-upstream quantiles; +Inf means beyond the last bucket."""
    head = ["UPSTREAM", "COUNT", "ERR", "MEAN", "P50", "P95", "P99"]

    def show(value: float) -> str:
        return "+Inf" if value == float("inf") else f"{value:.0f}ms"

    table = [head]
    for ns in sorted(summary):
        row = summary[ns]
        table.append(
            [
                ns,
                str(int(row["count"])),
                str(int(row["errors"])),
                show(row["mean_ms"]),
                show(row["p50_ms"]),
                show(row["p95_ms"]),
                show(row["p99_ms"]),
            ]
        )
    widths = [max(len(row[i]) for row in table) for i in range(len(head))]
    return "\n".join(
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        for row in table
    )
