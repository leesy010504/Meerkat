"""ES 이상 집계 결과를 주기적으로 폴링해 orchestrate()를 자동 호출한다."""

import asyncio
import datetime
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from elasticsearch import AsyncElasticsearch

from meerkat.agent.orchestrator import AlreadyCovered, ModelConfig, OrchestratorFailure, VerifyContext, orchestrate
from meerkat.config import Settings, load_settings
from meerkat.ingestion.pcap_capture import extract_flow_pcap, find_covering_files, list_pcap_log_files
from meerkat.llm.client import LLMClient, create_llm_client
from meerkat.mcp_server.tools.es_aggregate import es_aggregate
from meerkat.mcp_server.tools.es_query import es_query_events
from meerkat.storage.rule_memory import RuleItem, RuleMemory

logger = logging.getLogger(__name__)

# 집계 지표 → (근거 이벤트를 뽑을 인덱스, 역할 그룹 힌트)
METRIC_CONFIG: dict[str, tuple[str, str]] = {
    "unique_dst_ports_per_src": ("suricata-flow", "scanning"),
    "conn_count_per_src_port": ("suricata-flow", "scanning"),
    "unique_endpoints_per_src": ("nginx-access", "web-attack"),
    "http_4xx_ratio_per_src": ("nginx-access", "web-attack"),
    "request_rate_per_src": ("nginx-access", "web-attack"),
}


@dataclass
class SchedulerConfig:
    poll_interval_seconds: int = 300
    window_seconds: int = 300
    metrics: tuple[str, ...] = tuple(METRIC_CONFIG.keys())
    pcap_log_dir: str | None = None  # Suricata pcap-log 회전 파일 위치 (settings.paths.pcap_log_dir)


async def run_forever(
    *,
    es_client: AsyncElasticsearch,
    llm_client: LLMClient,
    rule_memory: RuleMemory,
    models: ModelConfig,
    verify_ctx: VerifyContext,
    scheduler_config: SchedulerConfig = SchedulerConfig(),
) -> None:
    while True:
        try:
            deployed = await poll_once(es_client, llm_client, rule_memory, models, verify_ctx, scheduler_config)
            if deployed:
                logger.info("scheduler cycle deployed %d rule(s)", len(deployed))
        except Exception:
            logger.exception("scheduler poll cycle failed, continuing")
        await asyncio.sleep(scheduler_config.poll_interval_seconds)


async def poll_once(
    es_client: AsyncElasticsearch,
    llm_client: LLMClient,
    rule_memory: RuleMemory,
    models: ModelConfig,
    verify_ctx: VerifyContext,
    config: SchedulerConfig,
) -> list[RuleItem]:
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(seconds=config.window_seconds)).isoformat()
    end = now.isoformat()

    deployed: list[RuleItem] = []

    for metric in config.metrics:
        sample_index, role_group_hint = METRIC_CONFIG[metric]

        aggregate = await es_aggregate(
            es_client, metric, start, end, config.window_seconds, top_n=10, compare_baseline=True
        )
        if aggregate.suggested_threshold is None:
            continue  # baseline 표본이 아직 부족함 — 판단 보류

        for offender in aggregate.top_offenders:
            if offender.value < aggregate.suggested_threshold:
                continue  # 평시 범위 안 — 트리거 아님

            flow_summary, repr_event_ids = await _build_flow_summary(
                es_client, sample_index, metric, offender, start, end
            )
            if flow_summary is None:
                continue

            repr_pcap_path = _try_extract_repr_pcap(sample_index, flow_summary, config.pcap_log_dir)
            call_verify_ctx = verify_ctx
            if repr_pcap_path is not None:
                # 이 이벤트의 pcap을 검증용 attack_pcaps에 추가한다
                call_verify_ctx = VerifyContext(
                    attack_pcaps=[*verify_ctx.attack_pcaps, repr_pcap_path],
                    benign_pcaps=verify_ctx.benign_pcaps,
                    suricata_binary=verify_ctx.suricata_binary,
                )

            try:
                item = await orchestrate(
                    flow_summary=flow_summary,
                    repr_event_ids=repr_event_ids,
                    repr_pcap_path=repr_pcap_path,
                    role_group_hint=role_group_hint,
                    llm_client=llm_client,
                    rule_memory=rule_memory,
                    models=models,
                    verify_ctx=call_verify_ctx,
                    suggested_threshold={
                        "count": aggregate.suggested_threshold,
                        "seconds": config.window_seconds,
                    },
                )
                logger.info("deployed sid=%s for metric=%s src_ip=%s", item.sid, metric, offender.src_ip)
                deployed.append(item)
            except AlreadyCovered as exc:
                logger.info(
                    "metric=%s src_ip=%s already covered by sid=%s, no action needed",
                    metric, offender.src_ip, exc.matched_sid,
                )
            except OrchestratorFailure:
                logger.warning(
                    "could not produce a verified rule for metric=%s src_ip=%s", metric, offender.src_ip
                )

    return deployed


async def _build_flow_summary(
    es_client: AsyncElasticsearch, index: str, metric: str, offender, start: str, end: str
) -> tuple[dict | None, list[str]]:
    samples = await es_query_events(es_client, index, start, end, src_ip=offender.src_ip, limit=5)
    if not samples:
        return None, []

    flow_summary = {
        "metric": metric,
        "src_ip": offender.src_ip,
        "observed_value": offender.value,
        "sample_events": samples,
    }
    return flow_summary, [s["_id"] for s in samples]


def _try_extract_repr_pcap(sample_index: str, flow_summary: dict, pcap_log_dir: str | None) -> str | None:
    """suricata-flow 소스이고 pcap_log_dir이 설정된 경우에만 pcap을 추출한다."""
    if pcap_log_dir is None or sample_index != "suricata-flow":
        return None

    sample_events = flow_summary.get("sample_events") or []
    if not sample_events:
        return None
    event = sample_events[0]

    required_fields = ("src_ip", "dest_ip", "src_port", "dest_port", "proto", "@timestamp")
    if not all(event.get(f) is not None for f in required_fields):
        return None

    files = list_pcap_log_files(pcap_log_dir)
    if not files:
        return None

    event_ts = datetime.datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00")).timestamp()
    covering = find_covering_files(files, event_ts - 30, event_ts + 30)
    if not covering:
        return None

    output_path = Path(pcap_log_dir) / "_extracted" / f"{event['_id']}.pcap"
    try:
        return extract_flow_pcap(
            covering,
            src_ip=event["src_ip"],
            dst_ip=event["dest_ip"],
            src_port=event["src_port"],
            dst_port=event["dest_port"],
            proto=event["proto"],
            output_path=output_path,
        )
    except Exception:
        logger.exception("failed to extract repr pcap for event %s", event.get("_id"))
        return None


def build_from_settings(settings: Settings) -> tuple[AsyncElasticsearch, LLMClient, RuleMemory, ModelConfig, VerifyContext]:
    es_client = AsyncElasticsearch(
        hosts=settings.elasticsearch.hosts,
        basic_auth=(
            (settings.elasticsearch.read_only_user, os.environ["MEERKAT_ES_PASSWORD"])
            if os.environ.get("MEERKAT_ES_PASSWORD")
            else None
        ),
    )
    llm_client = create_llm_client(settings.llm.provider)
    rule_memory = RuleMemory()
    models = ModelConfig(
        relation_assess=settings.llm.model_relation_assess,
        rule_generate=settings.llm.model_rule_generate,
        rule_repair=settings.llm.model_rule_repair,
        rule_select=settings.llm.model_sample_select,
    )
    verify_ctx = VerifyContext(
        attack_pcaps=[str(p) for p in Path(settings.paths.pcaps_attack).glob("*.pcap")],
        benign_pcaps=[str(p) for p in Path(settings.paths.pcaps_benign).glob("*.pcap")],
        suricata_binary=settings.suricata.binary,
    )
    return es_client, llm_client, rule_memory, models, verify_ctx


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = load_settings()
    es_client, llm_client, rule_memory, models, verify_ctx = build_from_settings(settings)
    await run_forever(
        es_client=es_client,
        llm_client=llm_client,
        rule_memory=rule_memory,
        models=models,
        verify_ctx=verify_ctx,
        scheduler_config=SchedulerConfig(pcap_log_dir=settings.paths.pcap_log_dir),
    )


if __name__ == "__main__":
    asyncio.run(main())
