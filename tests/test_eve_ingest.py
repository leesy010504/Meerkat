"""eve.json / nginx access log → ES 문서 변환과 실제 ES 적재를 검증한다."""

import datetime

import pytest
import pytest_asyncio
from elasticsearch import AsyncElasticsearch

from meerkat.ingestion.es_templates import build_all_templates
from meerkat.ingestion.eve_ingest import (
    bulk_index_documents,
    eve_to_document,
    index_name_for,
    nginx_lines_to_documents,
    parse_nginx_access_line,
    run_suricata_to_eve,
    shift_timestamps_to_now,
)
from meerkat.mcp_server.tools.es_aggregate import es_aggregate
from meerkat.mcp_server.tools.es_query import es_query_events

ES_URL = "http://localhost:9200"


def test_http_event_becomes_whitelisted_document():
    event = {
        "timestamp": "2026-09-01T23:04:53.287054+0900", "flow_id": 1, "event_type": "http",
        "src_ip": "0000:0000:0000:0000:0000:0000:0000:0001", "src_port": 53306,
        "dest_ip": "0000:0000:0000:0000:0000:0000:0000:0001", "dest_port": 8080, "proto": "TCP",
        "http": {"hostname": "localhost", "http_port": 8080, "url": "/backup",
                 "http_user_agent": "gobuster/3.8.2", "http_method": "GET", "status": 404, "length": 153,
                 "protocol": "HTTP/1.1", "request_headers": [{"name": "X", "value": "secret"}]},
    }
    prefix, doc = eve_to_document(event)
    assert prefix == "suricata-http"
    assert doc["src_ip"] == "::1" and doc["dest_ip"] == "::1"
    assert doc["http"]["url"] == "/backup" and doc["http"]["http_user_agent"] == "gobuster/3.8.2"
    assert "request_headers" not in doc["http"] and "http_port" not in doc["http"]  # 화이트리스트 밖
    assert index_name_for(prefix, doc["@timestamp"]) == "suricata-http-2026.09.01"  # UTC 기준 날짜


def test_non_ingested_event_types_are_dropped():
    assert eve_to_document({"event_type": "stats", "timestamp": "2026-09-01T00:00:00+0000"}) is None
    assert eve_to_document({"event_type": "fileinfo", "timestamp": "2026-09-01T00:00:00+0000"}) is None


def test_dns_v3_queries_are_normalized_to_rrname():
    event = {
        "timestamp": "2026-09-01T23:04:53+0000", "event_type": "dns", "src_ip": "10.0.0.5",
        "dest_ip": "10.0.0.53", "src_port": 5353, "dest_port": 53, "proto": "UDP",
        "dns": {"version": 3, "type": "answer", "rcode": "NOERROR",
                "queries": [{"rrname": "example.com", "rrtype": "A"}], "answers": [{}, {}]},
    }
    _, doc = eve_to_document(event)
    assert doc["dns"] == {"rcode": "NOERROR", "rrname": "example.com", "rrtype": "A", "answers_count": 2}


def test_shift_to_now_preserves_relative_spacing():
    docs = [
        ("suricata-flow", {"@timestamp": "2026-01-01T00:00:00+0000"}),
        ("suricata-flow", {"@timestamp": "2026-01-01T00:00:10+0000"}),
    ]
    now = datetime.datetime(2026, 10, 3, 12, 0, 0, tzinfo=datetime.timezone.utc)
    shifted = shift_timestamps_to_now(docs, now=now)
    ts = [datetime.datetime.fromisoformat(d["@timestamp"]) for _, d in shifted]
    assert ts[1] == now
    assert (ts[1] - ts[0]).total_seconds() == 10


def test_nginx_combined_line_is_parsed():
    line = '172.22.0.1 - - [03/Oct/2026:11:57:24 +0000] "GET /admin/?x=1 HTTP/1.1" 404 31 "-" "curl/8.7.1" "-"'
    doc = parse_nginx_access_line(line)
    assert doc["src_ip"] == "172.22.0.1"
    assert doc["nginx"]["path"] == "/admin/"  # 쿼리스트링은 떼고 경로만 (카디널리티 집계용)
    assert doc["nginx"]["status"] == 404 and doc["nginx"]["method"] == "GET"
    assert doc["nginx"]["user_agent"] == "curl/8.7.1"
    assert doc["@timestamp"].startswith("2026-10-03T11:57:24")
    assert parse_nginx_access_line("/docker-entrypoint.sh: Configuration complete") is None
    assert len(list(nginx_lines_to_documents([line, "garbage"]))) == 1


def test_real_pcap_through_suricata_yields_http_and_flow_documents():
    events = run_suricata_to_eve("pcaps/attack/dir_bruteforce.pcap")
    docs = [d for d in map(eve_to_document, events) if d is not None]
    prefixes = {prefix for prefix, _ in docs}
    assert {"suricata-http", "suricata-flow"} <= prefixes
    assert any(d["http"].get("http_user_agent", "").startswith("gobuster") for p, d in docs if p == "suricata-http")


# ---- 실제 ES ---------------------------------------------------------------------------


async def _es_available() -> bool:
    try:
        client = AsyncElasticsearch(hosts=[ES_URL])
        await client.info()
        await client.close()
        return True
    except Exception:
        return False


@pytest_asyncio.fixture
async def es_client():
    if not await _es_available():
        pytest.skip("local Elasticsearch not reachable at localhost:9200")
    client = AsyncElasticsearch(hosts=[ES_URL])
    for name, template in build_all_templates().items():
        await client.indices.put_index_template(
            name=f"meerkat-{name}", index_patterns=template["index_patterns"], template=template["template"]
        )
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y.%m.%d")
    indices = [f"suricata-http-{today}", f"suricata-flow-{today}", f"nginx-access-{today}"]
    await client.indices.delete(index=",".join(indices), ignore_unavailable=True)
    yield client
    await client.indices.delete(index=",".join(indices), ignore_unavailable=True)
    await client.close()


@pytest.mark.asyncio
async def test_ingested_pcap_is_queryable_through_parameterized_tools(es_client: AsyncElasticsearch):
    """pcap → eve → ES 적재 후 es_query_events/es_aggregate가 그대로 읽을 수 있어야 한다."""
    events = run_suricata_to_eve("pcaps/attack/dir_bruteforce.pcap")
    docs = shift_timestamps_to_now([d for d in map(eve_to_document, events) if d is not None])
    counts = await bulk_index_documents(es_client, docs)
    assert sum(counts.values()) == len(docs)

    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(minutes=5)).isoformat()
    end = (now + datetime.timedelta(minutes=1)).isoformat()

    http_hits = await es_query_events(es_client, "suricata-http", start, end, src_ip="::1", limit=50)
    assert http_hits, "ingested http events must be visible through es_query_events"
    assert all(set(h) <= {"_id", "@timestamp", "src_ip", "dest_ip", "http"} for h in http_hits)
    assert any(h["http"].get("http_user_agent", "").startswith("gobuster") for h in http_hits)

    result = await es_aggregate(es_client, "conn_count_per_src_port", start, end, 300, compare_baseline=False)
    assert result.top_offenders and result.top_offenders[0].src_ip == "::1"


@pytest.mark.asyncio
async def test_ingested_nginx_log_feeds_endpoint_cardinality_metric(es_client: AsyncElasticsearch):
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
    lines = [
        f'10.9.9.9 - - [{stamp}] "GET /p{i} HTTP/1.1" 404 153 "-" "gobuster/3.8.2" "-"' for i in range(40)
    ] + [f'10.1.1.1 - - [{stamp}] "GET / HTTP/1.1" 200 31 "-" "Mozilla/5.0" "-"']
    docs = list(nginx_lines_to_documents(lines))
    await bulk_index_documents(es_client, docs)

    start = (now - datetime.timedelta(minutes=5)).isoformat()
    end = (now + datetime.timedelta(minutes=1)).isoformat()
    result = await es_aggregate(es_client, "unique_endpoints_per_src", start, end, 300, compare_baseline=False)
    assert result.top_offenders[0].src_ip == "10.9.9.9"
    assert result.top_offenders[0].value == 40

    ratio = await es_aggregate(es_client, "http_4xx_ratio_per_src", start, end, 300, compare_baseline=False)
    by_ip = {o.src_ip: o.value for o in ratio.top_offenders}
    assert by_ip["10.9.9.9"] == 1.0 and by_ip["10.1.1.1"] == 0.0
