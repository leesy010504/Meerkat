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
    "failed_conn_ratio_per_src",
    "dns_query_rate_per_src",
]

_METRIC_INDEX: dict[str, str] = {
    "unique_dst_ports_per_src": "suricata-flow-*",
    "unique_endpoints_per_src": "nginx-access-*",
    "http_4xx_ratio_per_src": "nginx-access-*",
    "conn_count_per_src_port": "suricata-flow-*",
    "request_rate_per_src": "nginx-access-*",
    "failed_conn_ratio_per_src": "suricata-flow-*",
    "dns_query_rate_per_src": "suricata-dns-*",
}

_METRIC_CARDINALITY_FIELD: dict[str, str | None] = {
    "unique_dst_ports_per_src": "dest_port",
    "unique_endpoints_per_src": "nginx.path",
    "http_4xx_ratio_per_src": None,
    "conn_count_per_src_port": None,
    "request_rate_per_src": None,
    "failed_conn_ratio_per_src": None,
    "dns_query_rate_per_src": None,
}

# 비율(ratio) 계열 지표: (분모 필드, "매치"로 셀 값의 range 조건).
# failed_conn_ratio_per_src: 서버가 응답 패킷을 1개 이하로 보낸 플로우(무응답 또는
# RST 하나뿐)를 "실패한 연결 시도"로 본다 — 포트 스캔은 대부분 이 모양이고,
# 정상 요청-응답은 pkts_toclient가 최소 SYN-ACK+데이터로 2개 이상 나온다.
_METRIC_RATIO_CONFIG: dict[str, tuple[str, dict]] = {
    "http_4xx_ratio_per_src": ("nginx.status", {"gte": 400, "lt": 500}),
    "failed_conn_ratio_per_src": ("flow.pkts_toclient", {"lte": 1}),
}

# UDP는 핸드셰이크가 없어서 응답 패킷 1개가 정상 완료 상태다 — TCP에만 적용한다.
_METRIC_EXTRA_FILTER: dict[str, dict] = {
    "failed_conn_ratio_per_src": {"term": {"proto": "TCP"}},
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
    query = _build_query(metric, start, end)

    by_src: dict = {"terms": {"field": "src_ip", "size": top_n, "order": {"_count": "desc"}}}
    if metric in _METRIC_RATIO_CONFIG:
        ratio_field, ratio_range = _METRIC_RATIO_CONFIG[metric]
        by_src["aggs"] = {
            "total": {"value_count": {"field": ratio_field}},
            "matched": {"filter": {"range": {ratio_field: ratio_range}}},
        }
    elif field is not None:
        by_src["aggs"] = {"cardinality_value": {"cardinality": {"field": field}}}
        by_src["terms"]["order"] = {"cardinality_value": "desc"}

    response = await client.search(index=index, query=query, size=0, aggs={"by_src": by_src})
    buckets = response["aggregations"]["by_src"]["buckets"]

    offenders: list[Offender] = []
    for bucket in buckets:
        if metric in _METRIC_RATIO_CONFIG:
            total = bucket["total"]["value"] or 1
            value = bucket["matched"]["doc_count"] / total
        elif field is not None:
            value = bucket["cardinality_value"]["value"]
        else:
            value = bucket["doc_count"]
        offenders.append(Offender(src_ip=bucket["key"], value=value))

    return offenders


def _build_query(metric: str, start: str, end: str) -> dict:
    must: list[dict] = [{"range": {"@timestamp": {"gte": start, "lte": end}}}]
    extra_filter = _METRIC_EXTRA_FILTER.get(metric)
    if extra_filter is not None:
        must.append(extra_filter)
    return {"bool": {"must": must}}


async def _compute_baseline_distribution(
    client: AsyncElasticsearch, metric: str, window_seconds: int, baseline_days: int = 14
) -> list[float]:
    """최근 baseline_days 기간을 window_seconds 단위로 잘라 src_ip별 지표 분포를 계산한다."""
    index = _METRIC_INDEX[metric]
    field = _METRIC_CARDINALITY_FIELD[metric]

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=baseline_days)
    query = _build_query(metric, start.isoformat(), end.isoformat())

    by_src: dict = {"terms": {"field": "src_ip", "size": 1000}}
    if metric in _METRIC_RATIO_CONFIG:
        ratio_field, ratio_range = _METRIC_RATIO_CONFIG[metric]
        by_src["aggs"] = {
            "total": {"value_count": {"field": ratio_field}},
            "matched": {"filter": {"range": {ratio_field: ratio_range}}},
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
            if metric in _METRIC_RATIO_CONFIG:
                total = src_bucket["total"]["value"] or 1
                values.append(src_bucket["matched"]["doc_count"] / total)
            elif field is not None:
                values.append(src_bucket["cardinality_value"]["value"])
            else:
                values.append(src_bucket["doc_count"])

    return values
