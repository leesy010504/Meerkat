"""poll_once()가 이상 탐지 결과를 받아 orchestrate()를 호출하는지 검증한다."""

import datetime
import shutil
import subprocess
from pathlib import Path

import pytest
import pytest_asyncio
from elasticsearch import AsyncElasticsearch

from meerkat.agent.orchestrator import ModelConfig, VerifyContext
from meerkat.agent.schemas import RelationAssessOutput, RuleGenerateOutput
from meerkat.agent.scheduler import SchedulerConfig, poll_once
from meerkat.ingestion.es_templates import build_all_templates
from meerkat.storage.rule_memory import RuleMemory

from conftest import FakeLLMClient

ES_URL = "http://localhost:9200"
TEST_INDEX = "suricata-flow-000001"

MODELS = ModelConfig(relation_assess="fake", rule_generate="fake", rule_repair="fake", rule_select="fake")

# rules/scanning.rules와 동일한 포트스캔 탐지 룰
KNOWN_GOOD_SCAN_RULE = (
    'alert tcp any any -> any any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; '
    "flow:to_server; threshold:type threshold, track by_src, count 70, seconds 60; "
    "classtype:attempted-recon; sid:1000000; rev:1;)"
)


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
    await client.indices.delete(index=TEST_INDEX, ignore_unavailable=True)

    yield client

    await client.indices.delete(index=TEST_INDEX, ignore_unavailable=True)
    await client.close()


async def _seed_baseline_noise(es_client: AsyncElasticsearch, now: datetime.datetime) -> None:
    """baseline 계산에 필요한 최소 표본을 채우기 위해 정상 트래픽 이력을 넣는다."""
    for day_offset in range(10):
        for i in range(3):
            ts = now - datetime.timedelta(days=day_offset, hours=i)
            port_count = 1 + ((day_offset + i) % 6)
            for port in range(port_count):
                await es_client.index(
                    index=TEST_INDEX,
                    document={
                        "@timestamp": ts.isoformat(),
                        "src_ip": f"10.0.1.{day_offset * 3 + i}",
                        "dest_ip": "10.0.0.1",
                        "dest_port": 8000 + port,
                        "proto": "TCP",
                        "event_type": "flow",
                    },
                )


@pytest.mark.asyncio
async def test_poll_once_detects_anomaly_and_deploys_verified_rule(es_client: AsyncElasticsearch, tmp_path):
    """스캔성 트래픽을 이상으로 감지해 검증까지 통과한 룰을 배포하는지 확인한다."""
    now = datetime.datetime.now(datetime.timezone.utc)
    await _seed_baseline_noise(es_client, now)

    # 스캐너 하나가 80개 포트를 두드림
    for port in range(80):
        await es_client.index(
            index=TEST_INDEX,
            document={
                "@timestamp": now.isoformat(),
                "src_ip": "10.0.0.99",
                "dest_ip": "10.0.0.1",
                "dest_port": 2000 + port,
                "proto": "TCP",
                "event_type": "flow",
            },
        )
    await es_client.indices.refresh(index=TEST_INDEX)

    llm = FakeLLMClient()
    llm.queue(RelationAssessOutput(is_variant=False, matched_sid=None, reasoning="새 유형 — 포트 스캔"))
    llm.queue(RuleGenerateOutput(candidates=[KNOWN_GOOD_SCAN_RULE], attack_summary="port scan"))

    rule_memory = RuleMemory(path=tmp_path / "rule_memory.json")
    verify_ctx = VerifyContext(
        attack_pcaps=[str(p) for p in Path("pcaps/attack").glob("*.pcap")],
        benign_pcaps=[str(p) for p in Path("pcaps/benign").glob("*.pcap")],
    )

    config = SchedulerConfig(
        window_seconds=300,
        metrics=("unique_dst_ports_per_src",),
    )

    deployed = await poll_once(es_client, llm, rule_memory, MODELS, verify_ctx, config)

    assert len(deployed) == 1
    assert deployed[0].origin == "generated"
    assert deployed[0].role_group == "scanning"

    stored = await rule_memory.list()
    assert len(stored) == 1


@pytest.mark.asyncio
async def test_poll_once_skips_when_no_anomaly(es_client: AsyncElasticsearch, tmp_path):
    """baseline을 초과하는 offender가 없으면 orchestrate()를 부르지 않아야 한다."""
    now = datetime.datetime.now(datetime.timezone.utc)
    await _seed_baseline_noise(es_client, now)

    # 지금 이 순간의 트래픽: 정상적인 소수의 연결만 있음 — 이상 트래픽 아님
    for port in range(2):
        await es_client.index(
            index=TEST_INDEX,
            document={
                "@timestamp": now.isoformat(),
                "src_ip": "10.0.0.5",
                "dest_ip": "10.0.0.1",
                "dest_port": 443 + port,
                "proto": "TCP",
                "event_type": "flow",
            },
        )
    await es_client.indices.refresh(index=TEST_INDEX)

    llm = FakeLLMClient()  # 큐가 비어있음 — 호출되면 AssertionError로 즉시 실패
    rule_memory = RuleMemory(path=tmp_path / "rule_memory.json")
    verify_ctx = VerifyContext(attack_pcaps=[], benign_pcaps=[])
    config = SchedulerConfig(window_seconds=300, metrics=("unique_dst_ports_per_src",))

    deployed = await poll_once(es_client, llm, rule_memory, MODELS, verify_ctx, config)

    assert deployed == []
    assert llm.calls == []


@pytest.mark.asyncio
async def test_poll_once_extracts_repr_pcap_from_live_flow(es_client: AsyncElasticsearch, tmp_path):
    """pcap_log_dir이 설정돼 있으면 flow의 5-tuple로 pcap을 추출해 orchestrate()에 넘긴다."""
    now = datetime.datetime.now(datetime.timezone.utc)
    await _seed_baseline_noise(es_client, now)

    pcap_log_dir = tmp_path / "pcap_log"
    pcap_log_dir.mkdir()
    shutil.copy("pcaps/attack/auth_bruteforce.pcap", pcap_log_dir / "log.pcap.1000000000")

    for _ in range(80):
        await es_client.index(
            index=TEST_INDEX,
            document={
                "@timestamp": now.isoformat(),
                "src_ip": "127.0.0.1",
                "dest_ip": "127.0.0.1",
                "src_port": 53371,
                "dest_port": 2222,
                "proto": "TCP",
                "event_type": "flow",
            },
        )
    await es_client.indices.refresh(index=TEST_INDEX)

    llm = FakeLLMClient()
    llm.queue(RelationAssessOutput(is_variant=False, matched_sid=None, reasoning="새 유형 — 연결 폭주"))
    llm.queue(RuleGenerateOutput(candidates=[KNOWN_GOOD_SCAN_RULE], attack_summary="conn flood"))

    rule_memory = RuleMemory(path=tmp_path / "rule_memory.json")
    verify_ctx = VerifyContext(
        attack_pcaps=[str(p) for p in Path("pcaps/attack").glob("*.pcap")],
        benign_pcaps=[str(p) for p in Path("pcaps/benign").glob("*.pcap")],
    )
    config = SchedulerConfig(
        window_seconds=300,
        metrics=("conn_count_per_src_port",),
        pcap_log_dir=str(pcap_log_dir),
    )

    deployed = await poll_once(es_client, llm, rule_memory, MODELS, verify_ctx, config)

    assert len(deployed) == 1
    repr_pcap_path = deployed[0].repr_pcap_path
    assert repr_pcap_path is not None
    assert Path(repr_pcap_path).exists()

    # 추출된 pcap이 해당 5-tuple 플로우만 담고 있는지 확인
    result = subprocess.run(["tcpdump", "-nr", repr_pcap_path], capture_output=True, text=True)
    extracted_count = len([line for line in result.stdout.splitlines() if line.strip()])
    assert extracted_count == 32
