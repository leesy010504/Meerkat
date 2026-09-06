from datetime import datetime, timedelta, timezone
from typing import Literal

from elasticsearch import AsyncElasticsearch
from pydantic import BaseModel

from meerkat.ingestion.baseline import BaselineStats, compute_baseline
from meerkat.ingestion.baseline import suggested_threshold as _suggested_threshold

MIN_BASELINE_SAMPLES = 20

MetricName = Literal[
    "unique_dst_ports_per_src",
    "unique_endpoints_per_src",
    "http_4xx_ratio_per_src",
    "conn_count_per_src_port",
    "request_rate_per_src",
]

_METRIC_INDEX: dict[str, str] = {
    "unique_dst_ports_per_src": "suricata-flow-*",
    "unique_endpoints_per_src": "nginx-access-*",
    "http_4xx_ratio_per_src": "nginx-access-*",
    "conn_count_per_src_port": "suricata-flow-*",
    "request_rate_per_src": "nginx-access-*",
}

_METRIC_CARDINALITY_FIELD: dict[str, str | None] = {
    "unique_dst_ports_per_src": "dest_port",
    "unique_endpoints_per_src": "nginx.path",
    "http_4xx_ratio_per_src": None,
    "conn_count_per_src_port": None,
    "request_rate_per_src": None,
}


class Offender(BaseModel):
    src_ip: str
    value: float
    sample_event_ids: list[str] = []


class AggregateResult(BaseModel):
    metric: str
    window_seconds: int
    top_offenders: list[Offender]
    baseline: BaselineStats | None
    suggested_threshold: int | None


async def es_aggregate(
    client: AsyncElasticsearch,
    metric: MetricName,
    start: str,
    end: str,
    window_seconds: int,
    top_n: int = 20,
    compare_baseline: bool = True,
) -> AggregateResult:
    offenders = await _compute_offenders(client, metric, start, end, top_n)

    baseline = None
    threshold = None
    if compare_baseline:
        values = await _compute_baseline_distribution(client, metric, window_seconds)
        # 표본이 부족하면 판단을 보류한다
        if len(values) >= MIN_BASELINE_SAMPLES:
            baseline = compute_baseline(values)
            threshold = _suggested_threshold(baseline)

    return AggregateResult(
        metric=metric,
        window_seconds=window_seconds,
        top_offenders=offenders,
        baseline=baseline,
        suggested_threshold=threshold,
    )


async def _compute_offenders(
    client: AsyncElasticsearch, metric: str, start: str, end: str, top_n: int
) -> list[Offender]:
    index = _METRIC_INDEX[metric]
    field = _METRIC_CARDINALITY_FIELD[metric]
    query = {"range": {"@timestamp": {"gte": start, "lte": end}}}

    by_src: dict = {"terms": {"field": "src_ip", "size": top_n, "order": {"_count": "desc"}}}
    if metric == "http_4xx_ratio_per_src":
        by_src["aggs"] = {
            "total": {"value_count": {"field": "nginx.status"}},
            "errors": {"filter": {"range": {"nginx.status": {"gte": 400, "lt": 500}}}},
        }
    elif field is not None:
        by_src["aggs"] = {"cardinality_value": {"cardinality": {"field": field}}}
        by_src["terms"]["order"] = {"cardinality_value": "desc"}

    response = await client.search(index=index, query=query, size=0, aggs={"by_src": by_src})
    buckets = response["aggregations"]["by_src"]["buckets"]

    offenders: list[Offender] = []
    for bucket in buckets:
        if metric == "http_4xx_ratio_per_src":
            total = bucket["total"]["value"] or 1
            value = bucket["errors"]["doc_count"] / total
        elif field is not None:
            value = bucket["cardinality_value"]["value"]
        else:
            value = bucket["doc_count"]
        offenders.append(Offender(src_ip=bucket["key"], value=value))

    return offenders


async def _compute_baseline_distribution(
    client: AsyncElasticsearch, metric: str, window_seconds: int, baseline_days: int = 14
) -> list[float]:
    """최근 baseline_days 기간을 window_seconds 단위로 잘라 src_ip별 지표 분포를 계산한다."""
    index = _METRIC_INDEX[metric]
    field = _METRIC_CARDINALITY_FIELD[metric]

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=baseline_days)
    query = {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}

    by_src: dict = {"terms": {"field": "src_ip", "size": 1000}}
    if metric == "http_4xx_ratio_per_src":
        by_src["aggs"] = {
            "total": {"value_count": {"field": "nginx.status"}},
            "errors": {"filter": {"range": {"nginx.status": {"gte": 400, "lt": 500}}}},
        }
    elif field is not None:
        by_src["aggs"] = {"cardinality_value": {"cardinality": {"field": field}}}

    aggs = {
        "over_time": {
            "date_histogram": {"field": "@timestamp", "fixed_interval": f"{window_seconds}s"},
            "aggs": {"by_src": by_src},
        }
    }

    response = await client.search(index=index, query=query, size=0, aggs=aggs)

    values: list[float] = []
    for time_bucket in response["aggregations"]["over_time"]["buckets"]:
        for src_bucket in time_bucket["by_src"]["buckets"]:
            if metric == "http_4xx_ratio_per_src":
                total = src_bucket["total"]["value"] or 1
                values.append(src_bucket["errors"]["doc_count"] / total)
            elif field is not None:
                values.append(src_bucket["cardinality_value"]["value"])
            else:
                values.append(src_bucket["doc_count"])

    return values
