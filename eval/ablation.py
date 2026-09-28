"""핵심 실험(스펙 §11): 검증 루프가 룰 품질을 얼마나 끌어올리는가 — ablation 하네스.

같은 공격 시나리오(실제 캡처 pcap에서 뽑은 flow_summary + baseline 임계값)를 검증 단계를 단계별로
끈 조건에서 돌려 비교한다 (RulePilot ablation 표와 같은 축):

    none          : 검증 없음 — 첫 후보를 그대로 채택 (결정적 리라이트만)
    syntax        : 문법 검사만
    syntax_attack : 문법 + 공격 재현(트리거) 검사
    full          : 문법 + 트리거 + 정상 오탐 검사 (+ 역할 그룹) = 실제 파이프라인

조건별로 산출: SA(문법 통과율), DR(공격 pcap 트리거율), FPR(정상 pcap 오탐율),
SE=0.5·DR+0.5·(1−FPR), RC, LLM 호출 수, 수리 횟수. 결과는 eval/results/ablation-<provider>-<ts>.{json,md}.

    uv run python -m eval.ablation --provider template
    uv run python -m eval.ablation --provider gemini --conditions none,full

LLM은 설정의 provider(기본 gemini)를 쓴다. 무료 티어 일일 한도(모델당 20회)를 고려해 시나리오×조건
수를 정하라 — full 조건은 시나리오당 2~6회, none은 2회 정도 쓴다.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import meerkat.agent.orchestrator as orch
from eval.metrics import semantic_similarity
from meerkat.agent.audit import DecisionTrace
from meerkat.agent.orchestrator import (
    ModelConfig,
    OrchestratorFailure,
    VerifyContext,
    orchestrate,
)
from meerkat.config import load_settings
from meerkat.ingestion.eve_ingest import eve_to_document, run_suricata_to_eve
from meerkat.llm.client import LLMQuotaExhausted, create_llm_client
from meerkat.storage.rule_memory import RuleMemory
from meerkat.validation.deterministic_fix import apply_deterministic_fixes
from meerkat.validation.replay import replay_rule
from meerkat.validation.syntax import check_rule_syntax

logger = logging.getLogger("eval.ablation")

CONDITIONS = ("none", "syntax", "syntax_attack", "full")
MAX_LLM_CALLS = 8
INFRA_RETRIES = 2
INFRA_RETRY_DELAY_SECONDS = 60
MODEL_LABEL = "settings"
BENIGN_PCAPS = sorted(str(p) for p in Path("pcaps/benign").glob("*.pcap"))


@dataclass
class Scenario:
    name: str
    metric: str
    role_group_hint: str
    attack_pcap: str
    sample_index: str  # suricata-flow | suricata-http
    suggested_threshold: dict
    reference_rule: str | None = None
    # 같은 공격 계열(예: 빠른 스캔/느린 스캔)끼리는 서로의 pcap에서 울려도 오탐이 아니다.
    # 오탐 검사용 negative에서 같은 family의 공격 pcap은 뺀다.
    family: str = ""
    hard: bool = False


# 시나리오별 suggested_threshold는 데모/스케줄러가 쓰는 산출 방식(기준 지표 baseline p99×1.5)을
# 대신해, 정상 pcap 코퍼스에서 관찰되는 평시 수준을 넘는 값으로 고정한다 (실험 조건을 재현 가능하게).
SCENARIOS = [
    Scenario("port_scan", "unique_dst_ports_per_src", "scanning", "pcaps/attack/port_scan.pcap", "suricata-flow",
             {"count": 60, "seconds": 300, "basis_metric": "conn_count_per_src_port",
              "anomaly_metric": "unique_dst_ports_per_src"},
             reference_rule=Path("rules/scanning.rules").read_text().strip().splitlines()[0]),
    Scenario("ssh_bruteforce", "conn_count_per_src_port", "scanning", "pcaps/attack/auth_bruteforce.pcap",
             "suricata-flow",
             {"count": 10, "seconds": 300, "basis_metric": "conn_count_per_src_port",
              "anomaly_metric": "conn_count_per_src_port"},
             reference_rule=Path("rules/auth-bruteforce.rules").read_text().strip().splitlines()[0]),
    Scenario("dir_bruteforce", "unique_endpoints_per_src", "web-attack", "pcaps/attack/dir_bruteforce.pcap",
             "suricata-http",
             {"count": 30, "seconds": 300, "basis_metric": "request_rate_per_src",
              "anomaly_metric": "unique_endpoints_per_src"},
             reference_rule=Path("rules/web-attack.rules").read_text().strip().splitlines()[0]),
    Scenario("dns_query_burst", "dns_query_rate_per_src", "dns-flood", "pcaps/attack/dns_query_burst.pcap",
             "suricata-dns",
             {"count": 100, "seconds": 60, "basis_metric": "dns_query_rate_per_src",
              "anomaly_metric": "dns_query_rate_per_src"},
             reference_rule=Path("rules/dns-flood.rules").read_text().strip().splitlines()[0]),
    # ── 어려운 변형: 배포된 기준 룰을 피해 가도록 만든 시나리오 ──
    # 임계값은 기존 4개처럼 고정값이되, 정상 코퍼스의 분당 최대치×1.5로 잡았다 (스케줄러의 baseline 산출과 같은 방식).
    # 브라우저 UA 위장 디렉토리 탐색: UA 매칭이 안 통한다. 정상 브라우징이 30초에 요청 180개(404 20개)라
    # 요청 수만으로 좁히면 오탐 경계에 걸린다. 남는 신호는 404 비율. 정상 최대 180/분 ×1.5 = 270.
    Scenario("ua_spoofed_dirbust", "unique_endpoints_per_src", "web-attack", "pcaps/attack/ua_spoofed_dirbust.pcap",
             "suricata-http",
             {"count": 270, "seconds": 60, "basis_metric": "request_rate_per_src",
              "anomaly_metric": "unique_endpoints_per_src"},
             reference_rule=Path("rules/web-attack.rules").read_text().strip().splitlines()[1],
             family="dir_enum", hard=True),
    # 저속 포트 스캔: 초당 1개(분당 60개) 수준이라 배포된 scanning 룰(60초에 SYN 200개)도, 제안 임계값
    # (정상 브라우징 TCP 연결 140/분 ×1.5 = 210)도 지나간다. 창을 늘리거나 count를 낮추면 정상 브라우징과
    # 겹친다. 닫힌 포트의 RST처럼 스캔에만 있는 신호를 찾아야 한다.
    Scenario("slow_port_scan", "unique_dst_ports_per_src", "scanning", "pcaps/attack/slow_port_scan.pcap",
             "suricata-flow",
             {"count": 210, "seconds": 60, "basis_metric": "conn_count_per_src_port",
              "anomaly_metric": "unique_dst_ports_per_src"},
             reference_rule=Path("rules/scanning.rules").read_text().strip().splitlines()[1],
             family="port_scan", hard=True),
]
for _s in SCENARIOS:
    _s.family = _s.family or {"port_scan": "port_scan", "dir_bruteforce": "dir_enum"}.get(_s.name, _s.name)


def negative_pcaps(scenario: Scenario) -> list[str]:
    """정상 pcap + 다른 계열 공격 pcap (선택되지 않은 시나리오 것도 포함): 자기 공격만 잡아야 한다.

    기존 4개 시나리오는 이전 결과와 비교할 수 있게 기존 4개끼리만 negative로 쓴다. 어려운 변형은
    전체 카탈로그를 negative로 쓴다 — 예컨대 저속 스캔 룰이 UA 위장 탐색 pcap(14초에 연결 525개)에서
    울리면 "연결이 많은 출발지"를 잡은 것이지 스캔을 잡은 게 아니다.
    """
    pool = SCENARIOS if scenario.hard else [s for s in SCENARIOS if not s.hard]
    return BENIGN_PCAPS + [s.attack_pcap for s in pool
                           if s.family != scenario.family and Path(s.attack_pcap).exists()]


def select_scenarios(spec: str) -> list[Scenario]:
    """'base'(기존 4개, 기본) | 'hard' | 'all' | 쉼표로 나열한 이름."""
    if spec == "base":
        return [s for s in SCENARIOS if not s.hard]
    if spec == "hard":
        return [s for s in SCENARIOS if s.hard]
    if spec == "all":
        return list(SCENARIOS)
    names = spec.split(",")
    return [s for s in SCENARIOS if s.name in names]


def build_flow_summary(scenario: Scenario, suricata_binary: str, samples: int = 5) -> tuple[dict, list[str]]:
    """스케줄러의 _build_flow_summary와 같은 모양: 실제 pcap → eve → ES 문서 형태 샘플 5개."""
    events = run_suricata_to_eve(scenario.attack_pcap, suricata_binary)
    docs = [doc for prefix, doc in map(lambda e: eve_to_document(e) or (None, None), events)
            if prefix == scenario.sample_index]
    # 공격자 쪽 src_ip 기준으로 대표 샘플을 뽑는다 (가장 많이 등장하는 src_ip)
    from collections import Counter

    top_src = Counter(d["src_ip"] for d in docs).most_common(1)[0][0] if docs else "127.0.0.1"
    src_docs = sorted((d for d in docs if d["src_ip"] == top_src), key=lambda d: (d["@timestamp"], d.get("flow_id", 0)))
    # suricata 멀티스레드 출력 순서는 실행마다 달라서, 재현 가능하게 시각순 정렬 + 가장 흔한 목적지 포트 우선
    top_port = Counter(d.get("dest_port") for d in src_docs).most_common(1)[0][0] if src_docs else None
    chosen = [d for d in src_docs if d.get("dest_port") == top_port][:samples]
    chosen += [d for d in src_docs if d not in chosen][: samples - len(chosen)]
    for i, d in enumerate(chosen):
        d["_id"] = f"{scenario.name}-{i}"
    flow_summary = {
        "metric": scenario.metric, "src_ip": top_src,
        "observed_value": len([d for d in docs if d["src_ip"] == top_src]),
        "sample_events": chosen,
    }
    return flow_summary, [d["_id"] for d in chosen]


def make_verify(level: str, suricata_binary: str):
    """조건별 _verify 대체 구현. full은 원본 그대로."""
    original = orch._verify

    def verify(rule_text, attack_pcaps, benign_pcaps, binary):
        if level == "full":
            return original(rule_text, attack_pcaps, benign_pcaps, binary)
        fixed = apply_deterministic_fixes(rule_text).rule_text
        if orch.extract_action(fixed) != "alert":
            return False, fixed, orch.Diagnostic("policy:action must be alert")
        if level == "none":
            return True, fixed, "ok"
        syntax = check_rule_syntax(fixed, binary)
        if not syntax.ok:
            return False, fixed, orch.Diagnostic(f"syntax:{syntax.raw_output}")
        if level == "syntax":
            return True, fixed, "ok"
        attack = replay_rule(fixed, "attack", attack_pcaps, binary)
        if not attack.ok:
            return False, fixed, orch.Diagnostic(f"no_trigger:{attack.raw_output}")
        return True, fixed, "ok"  # syntax_attack: 정상 오탐 검사는 건너뜀

    return verify


@dataclass
class RuleOutcome:
    scenario: str
    condition: str
    produced: bool
    rule_text: str | None
    syntax_ok: bool
    triggers_attack: bool
    false_positive: bool
    role_group: str | None
    llm_calls: int
    repairs: dict
    semantic_similarity: float | None
    error: str | None = None
    attempts: list = field(default_factory=list)  # 검증 시도별 (phase, 결과, 실패 유형, 룰) — 사후 분석용


@dataclass
class ConditionSummary:
    condition: str
    rules: int = 0
    SA: float = 0.0
    DR: float = 0.0
    FPR: float = 0.0
    SE: float = 0.0
    SS: float | None = None
    llm_calls: int = 0
    repairs: int = 0
    failures: int = 0
    infra_errors: int = 0  # 503 등 외부 장애로 재시도 후에도 결과가 없는 시나리오 수 (지표에서 제외)
    truncated: bool = False  # LLM 한도로 중간에 멈췄으면 True — 이 조건의 수치는 일부 시나리오 기준
    outcomes: list[RuleOutcome] = field(default_factory=list)


def measure(rule_text: str, scenario: Scenario, binary: str, others: list[str] = ()) -> tuple[bool, bool, bool]:
    syntax_ok = check_rule_syntax(rule_text, binary).ok
    if not syntax_ok:
        return False, False, False
    triggers = replay_rule(rule_text, "attack", [scenario.attack_pcap], binary).ok
    fp = not replay_rule(rule_text, "benign", BENIGN_PCAPS + list(others), binary).ok
    return True, triggers, fp


async def run_condition(condition: str, scenarios: list[Scenario], provider: str, settings, workdir: Path,
                        role_groups_path: str) -> ConditionSummary:
    summary = ConditionSummary(condition=condition)
    orch._verify = make_verify(condition, settings.suricata.binary)  # type: ignore[assignment]
    try:
        for scenario in scenarios:
            llm = create_llm_client(provider)
            models = ModelConfig(
                relation_assess=settings.llm.model_relation_assess, rule_generate=settings.llm.model_rule_generate,
                rule_repair=settings.llm.model_rule_repair, rule_select=settings.llm.model_sample_select,
            )
            flow_summary, event_ids = build_flow_summary(scenario, settings.suricata.binary)
            infra_error: str | None = None
            for infra_try in range(INFRA_RETRIES + 1):
                # 시도마다 새 trace/메모리: 503으로 끊긴 시도의 호출 수가 지표에 섞이지 않게 한다
                trace = DecisionTrace(context={"condition": condition, "scenario": scenario.name})
                memory = RuleMemory(path=workdir / f"{condition}-{scenario.name}-{infra_try}-memory.json")
                outcome = RuleOutcome(scenario.name, condition, False, None, False, False, False, None, 0, {}, None)
                infra_error = None
                try:
                    item = await orchestrate(
                        flow_summary=flow_summary, repr_event_ids=event_ids, repr_pcap_path=None,
                        role_group_hint=scenario.role_group_hint, llm_client=llm, rule_memory=memory, models=models,
                        verify_ctx=VerifyContext(
                            attack_pcaps=[scenario.attack_pcap],
                            # 정상 pcap + 다른 계열 공격 pcap: 둘 다 조용해야 한다 (자기 공격만 잡기)
                            benign_pcaps=negative_pcaps(scenario),
                            suricata_binary=settings.suricata.binary,
                        ),
                        suggested_threshold=scenario.suggested_threshold, role_groups_path=role_groups_path,
                        trace=trace, max_llm_calls=MAX_LLM_CALLS,
                    )
                    outcome.produced, outcome.rule_text, outcome.role_group = True, item.rule_text, item.role_group
                except OrchestratorFailure as exc:
                    outcome.error = str(exc)[:200]
                    outcome.rule_text = exc.draft_rule_text
                    summary.failures += 1
                except LLMQuotaExhausted as exc:
                    # 이 시나리오는 결과가 없으니 넣지 않고, 이미 끝난 시나리오들로 부분 요약을 낸다
                    logger.error("[%s] %s: quota exhausted, truncating this condition: %s",
                                 condition, scenario.name, str(exc)[:120])
                    summary.truncated = True
                except Exception as exc:  # noqa: BLE001 - 503 등 외부 장애: 잠시 뒤 처음부터 다시
                    infra_error = f"{type(exc).__name__}: {exc}"[:200]
                    logger.error("[%s] %s infra error (try %d/%d): %s", condition, scenario.name,
                                 infra_try + 1, INFRA_RETRIES + 1, infra_error)
                    if infra_try < INFRA_RETRIES:
                        await asyncio.sleep(INFRA_RETRY_DELAY_SECONDS)
                        continue
                break
            if summary.truncated:
                break
            if infra_error is not None:
                # 모델 품질과 무관한 실패라 지표에서 뺀다 (DR 분모에 넣으면 503이 "미탐"으로 집계된다)
                summary.infra_errors += 1
                continue
            outcome.attempts = [
                {k: e.get(k) for k in ("phase", "attempt", "passed", "failure_kind", "rule")}
                for e in trace.events if e.get("event") == "verify"
            ]
            outcome.llm_calls = trace.llm_calls()
            outcome.repairs = trace.repair_types()
            # 채택된(또는 none 조건에서 그대로 통과한) 룰의 실제 품질을 전 조건 동일 기준으로 측정한다
            if outcome.produced and outcome.rule_text:
                outcome.syntax_ok, outcome.triggers_attack, outcome.false_positive = measure(
                    outcome.rule_text, scenario, settings.suricata.binary,
                    others=[p for p in negative_pcaps(scenario) if p not in BENIGN_PCAPS],
                )
                if scenario.reference_rule:
                    outcome.semantic_similarity = semantic_similarity(outcome.rule_text, scenario.reference_rule)
            summary.outcomes.append(outcome)
            summary.llm_calls += outcome.llm_calls
            summary.repairs += sum(outcome.repairs.values())
            logger.info("[%s] %s -> produced=%s syntax=%s trigger=%s fp=%s llm=%d",
                        condition, scenario.name, outcome.produced, outcome.syntax_ok, outcome.triggers_attack,
                        outcome.false_positive, outcome.llm_calls)
    finally:
        orch._verify = ORIGINAL_VERIFY  # type: ignore[assignment]

    produced = [o for o in summary.outcomes if o.produced]
    summary.rules = len(produced)
    if produced:
        summary.SA = sum(o.syntax_ok for o in produced) / len(produced)
        summary.DR = sum(o.triggers_attack for o in produced) / len(produced)
        summary.FPR = sum(o.false_positive for o in produced) / len(produced)
        ss = [o.semantic_similarity for o in produced if o.semantic_similarity is not None]
        summary.SS = sum(ss) / len(ss) if ss else None
    # 실패(룰 없음)는 탐지 못 한 것으로 DR 분모에 넣는다
    total = len(summary.outcomes)
    if total:
        summary.DR = sum(o.triggers_attack for o in summary.outcomes) / total
    summary.SE = 0.5 * summary.DR + 0.5 * (1 - summary.FPR)
    return summary


ORIGINAL_VERIFY = orch._verify


def render_markdown(summaries: list[ConditionSummary], provider: str, scenarios: list[Scenario]) -> str:
    lines = [
        f"# Ablation — provider `{provider}`, model `{MODEL_LABEL}`, scenarios: {', '.join(s.name for s in scenarios)}",
        "",
        "| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in summaries:
        ss = f"{s.SS:.2f}" if s.SS is not None else "-"
        done = (f"{len(s.outcomes)}/{len(scenarios)}" + (" (한도로 중단)" if s.truncated else "")
                + (f" (외부 장애 {s.infra_errors})" if s.infra_errors else ""))
        lines.append(f"| {s.condition} | {done} | {s.rules} | {s.SA:.2f} | {s.DR:.2f} | {s.FPR:.2f} | {s.SE:.3f} | {ss} "
                     f"| {s.llm_calls} | {s.repairs} | {s.failures} |")
    lines += ["", "## 룰별 결과", "", "| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for s in summaries:
        for o in s.outcomes:
            rule = (o.rule_text or o.error or "").replace("|", "\\|")
            lines.append(f"| {o.condition} | {o.scenario} | {'O' if o.produced else 'X'} | {'O' if o.syntax_ok else 'X'} "
                         f"| {'O' if o.triggers_attack else 'X'} | {'O' if o.false_positive else 'X'} | {o.role_group or '-'} "
                         f"| {o.llm_calls} | {sum(o.repairs.values())} | `{rule[:160]}` |")
    return "\n".join(lines) + "\n"


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--provider", default=None, help="gemini | anthropic | template (기본: settings.llm.provider)")
    parser.add_argument("--conditions", default=",".join(CONDITIONS))
    parser.add_argument("--scenarios", default="base",
                        help="base(기존 4개) | hard(UA 위장 탐색·저속 스캔) | all | 쉼표로 나열한 이름")
    parser.add_argument("--out-dir", default="eval/results")
    parser.add_argument("--max-llm-calls", type=int, default=8,
                        help="시나리오 하나당 LLM 호출 예산 (무료 티어 보호용, 기본 8)")
    parser.add_argument("--model", default=None,
                        help="모든 역할에 이 모델을 쓴다 (무료 티어 일일 한도는 모델별이라 실험을 모델에 분산할 때 유용)")
    args = parser.parse_args()
    global MAX_LLM_CALLS
    MAX_LLM_CALLS = args.max_llm_calls

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "elastic_transport", "google_genai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    settings = load_settings()
    if args.model:
        settings = settings.model_copy(update={"llm": settings.llm.model_copy(update={
            "model_relation_assess": args.model, "model_rule_generate": args.model,
            "model_rule_repair": args.model, "model_sample_select": args.model})})
    provider = args.provider or settings.llm.provider
    global MODEL_LABEL
    MODEL_LABEL = settings.llm.model_rule_generate if provider != "template" else "n/a"
    scenarios = select_scenarios(args.scenarios)
    conditions = [c for c in args.conditions.split(",") if c in CONDITIONS]

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # 병렬로 여러 모델을 돌려도 룰 메모리가 섞이지 않게 모델·pid까지 넣는다
    # (같은 초에 시작한 두 실행이 한 디렉토리를 공유해 "이미 커버됨"으로 오염된 적이 있다)
    workdir = Path(".meerkat/ablation") / f"{stamp}-{MODEL_LABEL}-{os.getpid()}"
    workdir.mkdir(parents=True, exist_ok=True)

    summaries: list[ConditionSummary] = []
    for condition in conditions:
        summary = await run_condition(condition, scenarios, provider, settings, workdir, "config/role_groups.yaml")
        if summary.outcomes:
            summaries.append(summary)
        if summary.truncated:
            logger.error("stopping early — LLM quota exhausted during condition %s", condition)
            break

    md = render_markdown(summaries, provider, scenarios)
    tag = f"{provider}-{MODEL_LABEL}" if provider != "template" else provider
    (out_dir / f"ablation-{tag}-{stamp}.md").write_text(md)
    (out_dir / f"ablation-{tag}-{stamp}.json").write_text(json.dumps(
        [{**{k: v for k, v in vars(s).items() if k != "outcomes"}, "outcomes": [vars(o) for o in s.outcomes]}
         for s in summaries], indent=2, ensure_ascii=False, default=str))
    print(md)
    print(f"saved: {out_dir}/ablation-{tag}-{stamp}.md")


if __name__ == "__main__":
    asyncio.run(main())
