"""ES 이상 집계 결과를 주기적으로 폴링해 orchestrate()를 자동 호출한다."""

import asyncio
import datetime
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from elasticsearch import AsyncElasticsearch

from meerkat.agent.audit import DecisionTrace
from meerkat.agent.category_propose import propose_category
from meerkat.agent.orchestrator import (
    AlreadyCovered,
    ModelConfig,
    OrchestratorFailure,
    VerifyContext,
    orchestrate,
)
from meerkat.config import Settings, load_settings
from meerkat.ingestion.baseline import suggested_threshold as _suggested_threshold
from meerkat.ingestion.pcap_capture import (
    extract_flow_pcap,
    find_covering_files,
    list_pcap_log_files,
)
from meerkat.llm.client import LLMClient, LLMQuotaExhausted, create_llm_client
from meerkat.mcp_server.tools.deploy import DEFAULT_DEPLOYMENT_GUIDE as _DEFAULT_GUIDE
from meerkat.mcp_server.tools.deploy import create_deploy_pr, deploy_rule_to_files
from meerkat.mcp_server.tools.es_aggregate import es_aggregate
from meerkat.mcp_server.tools.es_query import es_query_events
from meerkat.mcp_server.tools.rule_ops import sids_in_rules_dir
from meerkat.storage.failure_queue import FailureQueue
from meerkat.storage.rule_memory import RuleItem, RuleMemory
from meerkat.validation.corpus import build_verify_context, load_manifest

logger = logging.getLogger(__name__)

# 집계 지표 → (근거 이벤트를 뽑을 인덱스, 역할 그룹 힌트)
METRIC_CONFIG: dict[str, tuple[str, str]] = {
    "unique_dst_ports_per_src": ("suricata-flow", "scanning"),
    "conn_count_per_src_port": ("suricata-flow", "scanning"),
    "failed_conn_ratio_per_src": ("suricata-flow", "scanning"),
    "unique_endpoints_per_src": ("nginx-access", "web-attack"),
    "http_4xx_ratio_per_src": ("nginx-access", "web-attack"),
    "request_rate_per_src": ("nginx-access", "web-attack"),
    "dns_query_rate_per_src": ("suricata-dns", "dns-flood"),
}


# 이상 지표 → 룰의 threshold count가 실제로 세는 양에 맞는 "기준 지표".
#
# Suricata의 threshold/detection_filter는 "룰에 매치된 패킷 수"를 센다. 그런데 이상 탐지 지표는
# 그게 아닌 것들이 많다 — unique_dst_ports_per_src는 '고유 포트 수', *_ratio는 '비율'이다.
# 고유 포트 p99가 4라고 count 4를 쓰면, 브라우저 하나가 60초에 SYN 4개는 금방 넘겨서 정상
# 트래픽에서 바로 오탐이 난다 (로컬 E2E 데모에서 실제로 그렇게 됐다). 그래서 룰에 넣을 count는
# 같은 소스에서 "연결 수"/"요청 수" 같은 패킷 단위 지표의 baseline으로 따로 뽑는다.
# 이상 탐지(트리거) 자체는 원래 지표로 하고, 룰의 숫자만 기준 지표에서 가져온다.
METRIC_RULE_COUNT_BASIS: dict[str, str] = {
    "unique_dst_ports_per_src": "conn_count_per_src_port",
    "conn_count_per_src_port": "conn_count_per_src_port",
    "failed_conn_ratio_per_src": "conn_count_per_src_port",
    "unique_endpoints_per_src": "request_rate_per_src",
    "http_4xx_ratio_per_src": "request_rate_per_src",
    "request_rate_per_src": "request_rate_per_src",
    "dns_query_rate_per_src": "dns_query_rate_per_src",
}


@dataclass
class SchedulerConfig:
    poll_interval_seconds: int = 300
    window_seconds: int = 300
    metrics: tuple[str, ...] = tuple(METRIC_CONFIG.keys())
    pcap_log_dir: str | None = None  # Suricata pcap-log 회전 파일 위치 (settings.paths.pcap_log_dir)
    # 같은 (metric, src_ip) offender를 한 번 처리(배포/커버 확인/실패 기록)했으면 이 시간
    # 동안은 다시 LLM에 올리지 않는다. 스캔 하나가 여러 폴링 주기에 걸쳐 보이면 매 주기마다
    # 관계 판단 → 수리 사이클을 다시 도는 걸 막는다.
    offender_cooldown_seconds: int = 3600
    # 검증 통과 룰의 배포 방식 (settings.deploy). none이면 rule_memory에만 남긴다.
    deploy_mode: str = "none"
    rules_dir: str = "rules"
    proposals_dir: str | None = ".meerkat/deploy_proposals"
    deploy_repo_dir: str = "."
    # 의사결정 감사 로그(JSONL). None이면 기록하지 않는다.
    audit_log_path: str | None = ".meerkat/audit/decisions.jsonl"
    # 룰 count 산출: 기준 지표 baseline p99 × margin, 그리고 최소 count 하한 (count 1~3짜리 룰 방지)
    threshold_margin: float = 1.5
    min_rule_count: int = 5
    # 검증 코퍼스: pcaps/attack/manifest.yaml이 있으면 역할 그룹별로 positive/negative pcap을 나눈다
    # (validation/corpus.py). None이면 verify_ctx를 그대로 쓴다(공격 pcap 전부 positive).
    pcaps_attack_dir: str | None = None
    pcaps_benign_dir: str | None = None
    cross_group_negative: bool = True


@dataclass
class SchedulerState:
    """폴링 주기 사이에 남는 상태. run_forever가 하나 만들어 계속 넘긴다."""

    handled_offenders: dict[tuple[str, str], float] = field(default_factory=dict)

    def in_cooldown(self, metric: str, src_ip: str, cooldown_seconds: int, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        handled_at = self.handled_offenders.get((metric, src_ip))
        return handled_at is not None and (now - handled_at) < cooldown_seconds

    def mark_handled(self, metric: str, src_ip: str, now: float | None = None) -> None:
        self.handled_offenders[(metric, src_ip)] = time.monotonic() if now is None else now

    def prune(self, cooldown_seconds: int, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self.handled_offenders = {
            key: ts for key, ts in self.handled_offenders.items() if (now - ts) < cooldown_seconds
        }


async def run_forever(
    *,
    es_client: AsyncElasticsearch,
    llm_client: LLMClient,
    rule_memory: RuleMemory,
    models: ModelConfig,
    verify_ctx: VerifyContext,
    failure_queue: FailureQueue,
    scheduler_config: SchedulerConfig | None = None,
) -> None:
    scheduler_config = SchedulerConfig() if scheduler_config is None else scheduler_config
    state = SchedulerState()
    while True:
        sleep_seconds = scheduler_config.poll_interval_seconds
        try:
            deployed = await poll_once(
                es_client, llm_client, rule_memory, models, verify_ctx, failure_queue, scheduler_config,
                state=state,
            )
            if deployed:
                logger.info("scheduler cycle deployed %d rule(s)", len(deployed))
        except LLMQuotaExhausted as exc:
            # 할당량이 돌아올 때까지는 폴링해도 LLM 단계에서 다 막힌다 — 알려준 시간만큼 쉰다
            sleep_seconds = max(sleep_seconds, min(exc.retry_after_seconds or 3600, 6 * 3600))
            logger.error("LLM quota exhausted; pausing scheduler for %.0f s: %s", sleep_seconds, exc)
        except Exception:
            logger.exception("scheduler poll cycle failed, continuing")
        await asyncio.sleep(sleep_seconds)


async def poll_once(
    es_client: AsyncElasticsearch,
    llm_client: LLMClient,
    rule_memory: RuleMemory,
    models: ModelConfig,
    verify_ctx: VerifyContext,
    failure_queue: FailureQueue,
    config: SchedulerConfig,
    state: SchedulerState | None = None,
) -> list[RuleItem]:
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(seconds=config.window_seconds)).isoformat()
    end = now.isoformat()

    state = SchedulerState() if state is None else state
    state.prune(config.offender_cooldown_seconds)
    deployed: list[RuleItem] = []
    # rules/ 디렉토리에 손으로 넣은 룰의 sid와 충돌하지 않게 예약한다
    reserved_sids = sids_in_rules_dir(config.rules_dir) if Path(config.rules_dir).exists() else set()

    basis_cache: dict[str, int | None] = {}
    # 같은 출발지가 한 주기에 여러 지표(예: 고유 포트 수 + 연결 수)로 동시에 걸리는 건 보통 같은
    # 트래픽이다. 첫 지표에서 룰이 나왔으면(또는 이미 커버/실패 처리됐으면) 같은 주기의 나머지
    # 지표에서는 다시 올리지 않는다 — 안 그러면 거의 같은 룰이 두 개 생긴다.
    handled_src_this_cycle: set[str] = set()

    for metric in config.metrics:
        sample_index, role_group_hint = METRIC_CONFIG[metric]

        aggregate = await es_aggregate(
            es_client, metric, start, end, config.window_seconds, top_n=10, compare_baseline=True
        )
        if aggregate.suggested_threshold is None:
            continue  # baseline 표본이 아직 부족함 — 판단 보류

        rule_count = await _rule_count_for(es_client, metric, aggregate, start, end, config, basis_cache)
        if rule_count is None:
            logger.info("metric=%s: rule-count basis baseline not ready, skipping this cycle", metric)
            continue

        for offender in aggregate.top_offenders:
            if offender.value < aggregate.suggested_threshold:
                continue  # 평시 범위 안 — 트리거 아님
            if state.in_cooldown(metric, offender.src_ip, config.offender_cooldown_seconds):
                logger.debug("metric=%s src_ip=%s handled recently, skipping", metric, offender.src_ip)
                continue
            if offender.src_ip in handled_src_this_cycle:
                logger.info("metric=%s src_ip=%s already handled this cycle via another metric", metric, offender.src_ip)
                state.mark_handled(metric, offender.src_ip)
                continue

            flow_summary, repr_event_ids = await _build_flow_summary(
                es_client, sample_index, metric, offender, start, end
            )
            if flow_summary is None:
                continue

            repr_pcap_path = _try_extract_repr_pcap(sample_index, flow_summary, config.pcap_log_dir)
            call_verify_ctx = _verify_context_for(role_group_hint, verify_ctx, repr_pcap_path, config, metric)

            trace = DecisionTrace(context={
                "metric": metric, "src_ip": offender.src_ip, "observed_value": offender.value,
                "suggested_threshold": aggregate.suggested_threshold, "rule_count": rule_count,
                "window_seconds": config.window_seconds,
                "role_group_hint": role_group_hint, "repr_pcap_path": repr_pcap_path,
            })
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
                        "count": rule_count,
                        "seconds": config.window_seconds,
                        "basis_metric": METRIC_RULE_COUNT_BASIS.get(metric, metric),
                        "anomaly_metric": metric,
                        "anomaly_threshold": aggregate.suggested_threshold,
                        "anomaly_value": offender.value,
                    },
                    reserved_sids=reserved_sids,
                    trace=trace,
                )
                logger.info("verified sid=%s for metric=%s src_ip=%s", item.sid, metric, offender.src_ip)
                await _deploy(item, config, metric, offender.src_ip, trace)
                deployed.append(item)
                state.mark_handled(metric, offender.src_ip)
                handled_src_this_cycle.add(offender.src_ip)
            except AlreadyCovered as exc:
                logger.info(
                    "metric=%s src_ip=%s already covered by sid=%s, no action needed",
                    metric, offender.src_ip, exc.matched_sid,
                )
                state.mark_handled(metric, offender.src_ip)
                handled_src_this_cycle.add(offender.src_ip)
            except LLMQuotaExhausted:
                # 이 offender는 처리 못 했으니 쿨다운에 넣지 않는다 (할당량 복구 후 다시 올라와야 함).
                # 같은 주기의 나머지 offender도 전부 같은 벽에 막히므로 여기서 주기를 끝낸다.
                if config.audit_log_path:
                    trace.record("outcome", result="llm_quota_exhausted")
                    trace.append_jsonl(config.audit_log_path)
                raise
            except OrchestratorFailure as exc:
                state.mark_handled(metric, offender.src_ip)
                logger.warning(
                    "could not produce a verified rule for metric=%s src_ip=%s", metric, offender.src_ip
                )
                proposal = None
                try:
                    proposal = await propose_category(
                        llm_client, flow_summary, str(exc), exc.draft_rule_text, models.relation_assess,
                    )
                except Exception:
                    logger.exception(
                        "category proposal failed for metric=%s src_ip=%s, recording without one",
                        metric, offender.src_ip,
                    )
                await failure_queue.add(
                    metric=metric,
                    role_group_hint=role_group_hint,
                    src_ip=offender.src_ip,
                    reason=str(exc),
                    flow_summary=flow_summary,
                    draft_rule_text=exc.draft_rule_text,
                    proposed_category=proposal.candidate_category_name if proposal else None,
                    proposed_role_group=(
                        proposal.model_dump(exclude={"candidate_category_name", "reasoning"})
                        if proposal
                        else None
                    ),
                    proposal_reasoning=proposal.reasoning if proposal else None,
                )
            finally:
                if config.audit_log_path and trace.outcome() != "llm_quota_exhausted":
                    trace.append_jsonl(config.audit_log_path)

    return deployed


def _verify_context_for(
    role_group_hint: str, base: VerifyContext, repr_pcap_path: str | None, config: SchedulerConfig,
    metric: str | None = None,
) -> VerifyContext:
    """매니페스트가 있으면 트리거 지표(없으면 역할 그룹) 기준 positive/negative 코퍼스, 없으면 기본 컨텍스트."""
    if config.pcaps_attack_dir and config.pcaps_benign_dir:
        manifest = load_manifest(config.pcaps_attack_dir)
        if manifest:
            return build_verify_context(
                role_group_hint, config.pcaps_attack_dir, config.pcaps_benign_dir, manifest,
                suricata_binary=base.suricata_binary, repr_pcap=repr_pcap_path,
                cross_group_negative=config.cross_group_negative, metric=metric,
            )
    if repr_pcap_path is None:
        return base
    # 이 이벤트의 pcap을 검증용 attack_pcaps에 추가한다
    return VerifyContext(
        attack_pcaps=[*base.attack_pcaps, repr_pcap_path],
        benign_pcaps=base.benign_pcaps,
        suricata_binary=base.suricata_binary,
    )


async def _rule_count_for(
    es_client, metric: str, aggregate, start: str, end: str, config: SchedulerConfig,
    cache: dict[str, int | None],
) -> int | None:
    """룰 threshold에 넣을 count — METRIC_RULE_COUNT_BASIS 기준 지표의 baseline p99 × margin, 하한 적용."""
    basis = METRIC_RULE_COUNT_BASIS.get(metric, metric)
    if basis not in cache:
        if basis == metric:
            # 같은 지표면 이미 계산한 baseline을 margin만 다시 적용해 쓴다
            cache[basis] = (
                _suggested_threshold(aggregate.baseline, config.threshold_margin) if aggregate.baseline else None
            )
        else:
            basis_aggregate = await es_aggregate(
                es_client, basis, start, end, config.window_seconds, top_n=1, compare_baseline=True,
                threshold_margin=config.threshold_margin,
            )
            cache[basis] = basis_aggregate.suggested_threshold
    count = cache[basis]
    if count is None:
        return None
    return max(count, config.min_rule_count)


async def _deploy(
    item: RuleItem, config: SchedulerConfig, metric: str, src_ip: str, trace: DecisionTrace | None = None
) -> None:
    """settings.deploy.mode에 따라 rules/ 파일 반영(+제안서) 또는 PR 생성까지 한다."""
    if config.deploy_mode == "none":
        return
    result = deploy_rule_to_files(
        item, config.rules_dir, config.proposals_dir, metric, src_ip,
        trace_lines=trace.summary_lines() if trace else None,
    )
    logger.info(
        "wrote sid=%s to %s (%s)%s", item.sid, result.rule_file,
        "replaced previous rev" if result.replaced_existing else "appended",
        f", proposal: {result.proposal_file}" if result.proposal_file else "",
    )
    if config.deploy_mode == "pr":
        pr = await create_deploy_pr(
            item.rule_text, item.sid, item.role_group,
            rationale=item.rationale or "(기록 없음)",
            evidence_event_ids=item.repr_event_ids,
            deployment_guide=_DEFAULT_GUIDE,
            rules_dir=config.rules_dir, repo_dir=config.deploy_repo_dir,
        )
        if pr.ok:
            logger.info("opened PR %s on branch %s", pr.pr_url, pr.branch)
        else:
            logger.error("PR creation failed on branch %s: %s", pr.branch, pr.raw_output.strip()[:500])


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


def build_from_settings(
    settings: Settings,
) -> tuple[AsyncElasticsearch, LLMClient, RuleMemory, ModelConfig, VerifyContext, FailureQueue]:
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
    failure_queue = FailureQueue()
    return es_client, llm_client, rule_memory, models, verify_ctx, failure_queue


def _build_scheduler_config(settings: Settings, args) -> SchedulerConfig:
    return SchedulerConfig(
        poll_interval_seconds=args.poll_interval or SchedulerConfig.poll_interval_seconds,
        window_seconds=args.window or SchedulerConfig.window_seconds,
        metrics=tuple(m.strip() for m in args.metrics.split(",")) if args.metrics else tuple(METRIC_CONFIG.keys()),
        pcap_log_dir=settings.paths.pcap_log_dir,
        deploy_mode=settings.deploy.mode,
        rules_dir=settings.paths.rules_dir,
        proposals_dir=settings.deploy.proposals_dir,
        deploy_repo_dir=settings.deploy.repo_dir,
        audit_log_path=settings.deploy.audit_log_path,
        pcaps_attack_dir=settings.paths.pcaps_attack,
        pcaps_benign_dir=settings.paths.pcaps_benign,
    )


async def main(argv: list[str] | None = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="ES 이상 집계를 폴링해 orchestrate()를 자동 호출하는 스케줄러",
    )
    parser.add_argument("--once", action="store_true", help="한 주기만 돌고 종료한다 (cron/수동 점검용)")
    parser.add_argument("--provider", default=None, help="settings.llm.provider 대신 쓸 프로바이더 (gemini|anthropic|template)")
    parser.add_argument("--model", default=None, help="모든 역할에 이 모델을 쓴다")
    parser.add_argument("--poll-interval", type=int, default=None, help="폴링 간격(초)")
    parser.add_argument("--window", type=int, default=None, help="집계 윈도우(초)")
    parser.add_argument("--metrics", default=None, help="콤마 구분 지표 목록 (기본: 전부)")
    parser.add_argument("--settings", default="config/settings.yaml")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for noisy in ("elastic_transport", "httpx", "google_genai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    settings = load_settings(args.settings)
    if args.provider:
        settings = settings.model_copy(update={"llm": settings.llm.model_copy(update={"provider": args.provider})})
    if args.model:
        settings = settings.model_copy(update={"llm": settings.llm.model_copy(update={
            "model_relation_assess": args.model, "model_rule_generate": args.model,
            "model_rule_repair": args.model, "model_sample_select": args.model})})
    es_client, llm_client, rule_memory, models, verify_ctx, failure_queue = build_from_settings(settings)
    config = _build_scheduler_config(settings, args)
    logger.info("scheduler start: provider=%s metrics=%s deploy=%s once=%s",
                settings.llm.provider, ",".join(config.metrics), config.deploy_mode, args.once)
    try:
        if args.once:
            deployed = await poll_once(
                es_client, llm_client, rule_memory, models, verify_ctx, failure_queue, config, state=SchedulerState()
            )
            logger.info("single cycle done: %d rule(s) deployed", len(deployed))
            return
        await run_forever(
            es_client=es_client, llm_client=llm_client, rule_memory=rule_memory, models=models,
            verify_ctx=verify_ctx, failure_queue=failure_queue, scheduler_config=config,
        )
    finally:
        await es_client.close()


if __name__ == "__main__":
    asyncio.run(main())
