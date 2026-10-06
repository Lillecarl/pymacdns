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

    def summary(self) -> list[UpstreamSummary]:
        return [
            UpstreamSummary(
                nameserver=ns,
                count=histogram.count,
                errors=histogram.errors,
                mean_ms=histogram.mean(),
                p50_ms=histogram.quantile(0.5),
                p95_ms=histogram.quantile(0.95),
                p99_ms=histogram.quantile(0.99),
            )
            for ns, histogram in sorted(self.histograms.items())
        ]


@dataclass
class UpstreamSummary:
    nameserver: str
    count: int
    errors: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float

    def payload(self) -> dict[str, float]:
        """The JSON-facing shape: everything but the key it hangs under."""
        return {
            "count": self.count,
            "errors": self.errors,
            "mean_ms": self.mean_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
        }


def format_table(summaries: list[UpstreamSummary]) -> str:
    """Align per-upstream quantiles; +Inf means beyond the last bucket."""
    head = ["UPSTREAM", "COUNT", "ERR", "MEAN", "P50", "P95", "P99"]

    def show(value: float) -> str:
        return "+Inf" if value == float("inf") else f"{value:.0f}ms"

    table = [head]
    for summary in summaries:
        table.append(
            [
                summary.nameserver,
                str(summary.count),
                str(summary.errors),
                show(summary.mean_ms),
                show(summary.p50_ms),
                show(summary.p95_ms),
                show(summary.p99_ms),
            ]
        )
    widths = [max(len(row[i]) for row in table) for i in range(len(head))]
    return "\n".join(
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        for row in table
    )
