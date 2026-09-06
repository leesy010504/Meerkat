"""로컬 ES에 인덱스 템플릿을 적용하고 es_query_events / es_aggregate를 검증한다.
ES가 떠 있지 않으면 스킵한다."""

import datetime

import pytest
import pytest_asyncio
from elasticsearch import AsyncElasticsearch

from meerkat.ingestion.es_templates import build_all_templates
from meerkat.mcp_server.tools.es_aggregate import es_aggregate
from meerkat.mcp_server.tools.es_query import es_query_events

ES_URL = "http://localhost:9200"
TEST_INDEX = "suricata-flow-000001"


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
            name=f"meerkat-{name}",
            index_patterns=template["index_patterns"],
            template=template["template"],
        )

    await client.indices.delete(index=TEST_INDEX, ignore_unavailable=True)

    yield client

    await client.indices.delete(index=TEST_INDEX, ignore_unavailable=True)
    await client.close()


@pytest.mark.asyncio
async def test_es_query_events_returns_indexed_flow(es_client: AsyncElasticsearch):
    index = TEST_INDEX
    now = datetime.datetime.now(datetime.timezone.utc)

    docs = []
    for i in range(5):
        docs.append(
            {
                "@timestamp": (now - datetime.timedelta(seconds=i)).isoformat(),
                "src_ip": "10.0.0.5",
                "dest_ip": "10.0.0.1",
                "dest_port": 1000 + i,
                "src_port": 40000,
                "proto": "TCP",
                "event_type": "flow",
                "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "age": 1, "state": "closed"},
            }
        )

    for doc in docs:
        await es_client.index(index=index, document=doc, refresh=True)

    results = await es_query_events(
        es_client,
        "suricata-flow",
        start=(now - datetime.timedelta(minutes=1)).isoformat(),
        end=(now + datetime.timedelta(minutes=1)).isoformat(),
        src_ip="10.0.0.5",
    )

    assert len(results) == 5
    assert all(r["src_ip"] == "10.0.0.5" for r in results)


@pytest.mark.asyncio
async def test_es_aggregate_unique_dst_ports_detects_scan(es_client: AsyncElasticsearch):
    index = TEST_INDEX
    now = datetime.datetime.now(datetime.timezone.utc)

    # 스캐너 하나가 80개 포트를 두드림
    for port in range(80):
        await es_client.index(
            index=index,
            document={
                "@timestamp": now.isoformat(),
                "src_ip": "10.0.0.99",
                "dest_ip": "10.0.0.1",
                "dest_port": 2000 + port,
                "proto": "TCP",
                "event_type": "flow",
            },
        )
    await es_client.indices.refresh(index=index)

    result = await es_aggregate(
        es_client,
        "unique_dst_ports_per_src",
        start=(now - datetime.timedelta(minutes=1)).isoformat(),
        end=(now + datetime.timedelta(minutes=1)).isoformat(),
        window_seconds=60,
        compare_baseline=False,
    )

    assert result.top_offenders, "no offenders returned"
    top = result.top_offenders[0]
    assert top.src_ip == "10.0.0.99"
    assert top.value >= 70
