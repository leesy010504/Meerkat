"""sid별 알럿량 리포트가 실제 ES 집계로 noisy sid를 표시하는지 검증한다. ES가 없으면 skip."""

import datetime
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from elasticsearch import AsyncElasticsearch

from meerkat.ingestion.es_templates import build_all_templates

sys.path.insert(0, str(Path("scripts").resolve()))
from rule_alert_report import collect  # noqa: E402

ES_URL = "http://localhost:9200"


@pytest_asyncio.fixture
async def es_client():
    client = AsyncElasticsearch(hosts=[ES_URL])
    try:
        await client.info()
    except Exception:
        await client.close()
        pytest.skip("local Elasticsearch not reachable")
    for name, template in build_all_templates().items():
        await client.indices.put_index_template(
            name=f"meerkat-{name}", index_patterns=template["index_patterns"], template=template["template"]
        )
    index = f"suricata-alert-{datetime.datetime.now(datetime.timezone.utc):%Y.%m.%d}"
    await client.indices.delete(index=index, ignore_unavailable=True)
    yield client, index
    await client.indices.delete(index=index, ignore_unavailable=True)
    await client.close()


@pytest.mark.asyncio
async def test_noisy_sid_is_flagged(es_client, monkeypatch, tmp_path):
    client, index = es_client
    monkeypatch.chdir(tmp_path)  # RuleMemory 기본 경로(.meerkat/)를 임시 디렉토리로
    now = datetime.datetime.now(datetime.timezone.utc)
    for sid, count, srcs in ((1000001, 90, 3), (1000002, 10, 5)):
        for i in range(count):
            await client.index(index=index, document={
                "@timestamp": (now - datetime.timedelta(minutes=i % 50)).isoformat(),
                "src_ip": f"10.0.0.{i % srcs}", "event_type": "alert",
                "alert": {"signature_id": sid, "signature": "x", "severity": 2},
            })
    await client.indices.refresh(index=index)

    report = await collect(client, hours=1, noisy_share=0.5)
    rows = {r["sid"]: r for r in report["rules"]}
    assert report["total_alerts"] == 100
    assert rows[1000001]["alerts"] == 90 and rows[1000001]["noisy"] is True
    assert rows[1000001]["unique_src_ips"] == 3
    assert rows[1000002]["noisy"] is False and rows[1000002]["origin"] == "unknown"
