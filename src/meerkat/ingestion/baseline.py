import statistics

from pydantic import BaseModel


class BaselineStats(BaseModel):
    p50: float
    p95: float
    p99: float
    mean: float
    std: float


def compute_baseline(values: list[float]) -> BaselineStats:
    if not values:
        raise ValueError("no baseline samples")

    sorted_vals = sorted(values)
    return BaselineStats(
        p50=_percentile(sorted_vals, 50),
        p95=_percentile(sorted_vals, 95),
        p99=_percentile(sorted_vals, 99),
        mean=statistics.fmean(values),
        std=statistics.pstdev(values) if len(values) > 1 else 0.0,
    )


def suggested_threshold(baseline: BaselineStats, margin: float = 1.0) -> int:
    """p99 기반 임계값 후보를 계산한다. margin은 p99에 곱하는 배수."""
    return max(1, round(baseline.p99 * margin))


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if len(sorted_vals) == 1:
        return sorted_vals[0]

    k = (len(sorted_vals) - 1) * (pct / 100)
    lower = int(k)
    upper = min(lower + 1, len(sorted_vals) - 1)
    if lower == upper:
        return sorted_vals[lower]
    return sorted_vals[lower] + (sorted_vals[upper] - sorted_vals[lower]) * (k - lower)
