import logging
from dataclasses import dataclass

from meerkat.agent.audit import DecisionTrace
from meerkat.agent.memory_update import (
    record_covered_evidence,
    record_generated_rule,
    record_repaired_rule,
)
from meerkat.agent.relation_assess import assess_relation
from meerkat.agent.rule_generate import generate_rules
from meerkat.agent.rule_repair import FailureType, repair_rule
from meerkat.agent.rule_select import select_best_candidate
from meerkat.agent.schemas import RelationAssessOutput
from meerkat.llm.client import LLMClient
from meerkat.mcp_server.tools.deploy import assign_role_group
from meerkat.mcp_server.tools.rule_ops import allocate_sid
from meerkat.security.injection_filter import filter_flow_fields_with_report
from meerkat.storage.rule_memory import RuleItem, RuleMemory
from meerkat.validation.deterministic_fix import (
    apply_deterministic_fixes,
    extract_action,
    set_sid_and_rev,
)
from meerkat.validation.error_kb import classify_error
from meerkat.validation.logic_check import RoleGroupDef, load_role_groups
from meerkat.validation.replay import replay_rule
from meerkat.validation.syntax import check_rule_syntax
from meerkat.validation.threshold_calibrate import (
    calibrate_threshold,
    extract_threshold_count,
    find_separating_threshold,
)
from meerkat.validation.traffic_profile import traffic_contrast

logger = logging.getLogger(__name__)

K_MAX = 3  # 룰 하나당 수리 재시도 횟수
N_MAX = 2  # 롤백 반복 상한
MAX_LLM_CALLS = 12  # 샘플 하나당 LLM 호출 예산 (무료 티어 일일 한도가 20회라 한 샘플이 다 태우면 안 된다)


class OrchestratorFailure(Exception):
    """마지막으로 시도한 룰 초안이 있으면 draft_rule_text에 담아둔다.

    문법 검사조차 통과 못한 초안이 담길 수도 있다 — 사람이 검토할 후보일 뿐,
    검증을 통과한 배포 가능한 룰이라는 보장은 아니다.
    """

    def __init__(self, message: str, draft_rule_text: str | None = None):
        self.draft_rule_text = draft_rule_text
        super().__init__(message)


class AlreadyCovered(Exception):
    """현재 룰셋이 이미 이 트래픽을 탐지하고 있음을 나타낸다."""

    def __init__(self, matched_sid: int):
        self.matched_sid = matched_sid
        super().__init__(f"traffic already covered by existing rule sid={matched_sid}")


class Diagnostic(str):
    """_verify의 실패 진단. `"<kind>:<detail>"` 문자열이면서, 오탐 수리 프롬프트에 넘길
    구조화된 플로우 샘플(samples)을 함께 들고 다닌다. 테스트 스텁이 평범한 str을
    돌려줘도 그대로 동작하도록 str을 상속한다."""

    samples: list[dict]

    def __new__(cls, text: str, samples: list[dict] | None = None):
        obj = super().__new__(cls, text)
        obj.samples = list(samples or [])
        return obj


# LLM에 넘기는 suricata 원문 출력 상한 — 전체 로그는 수천 자라 토큰만 잡아먹는다
_MAX_RAW_OUTPUT_CHARS = 1500


@dataclass
class ModelConfig:
    relation_assess: str
    rule_generate: str
    rule_repair: str
    rule_select: str


@dataclass
class VerifyContext:
    attack_pcaps: list[str]
    benign_pcaps: list[str]
    suricata_binary: str = "suricata"


async def orchestrate(
    *,
    flow_summary: dict,
    repr_event_ids: list[str],
    repr_pcap_path: str | None,
    role_group_hint: str,
    llm_client: LLMClient,
    rule_memory: RuleMemory,
    models: ModelConfig,
    verify_ctx: VerifyContext,
    suggested_threshold: dict | None = None,
    sid_range: tuple[int, int] = (1000000, 1999999),
    role_groups_path: str = "config/role_groups.yaml",
    reserved_sids: set[int] | None = None,
    trace: DecisionTrace | None = None,
    max_llm_calls: int = MAX_LLM_CALLS,
) -> RuleItem:
    """reserved_sids: rule_memory 밖에서 이미 쓰이는 sid(예: rules/*.rules에 손으로 넣은 룰).
    신규 sid 할당 시 이들과도 충돌하지 않게 한다.
    trace: 의사결정 감사 로그. 호출자가 넘기면 모든 판단 단계가 기록된다 (audit.py)."""
    trace = DecisionTrace() if trace is None else trace

    # 진입점에서 한 번만 인젝션 필터를 적용한다
    flow_summary, blanked_fields = filter_flow_fields_with_report(flow_summary)
    trace.record("injection_filter", blanked_fields=blanked_fields)
    if blanked_fields:
        logger.warning(
            "injection filter blanked %d field(s) before LLM: %s", len(blanked_fields), blanked_fields
        )
    role_groups = load_role_groups(role_groups_path)

    # 현재 룰셋으로 이미 탐지되는지 먼저 확인한다
    if repr_pcap_path is not None:
        existing_rules = await rule_memory.list()
        covering_sid = _check_already_covered(
            existing_rules, repr_pcap_path, verify_ctx.suricata_binary
        )
        trace.record("already_covered_check", rules=len(existing_rules), covering_sid=covering_sid)
        if covering_sid is not None:
            trace.record("outcome", result="already_covered", sid=covering_sid)
            raise AlreadyCovered(covering_sid)

    force_new = False
    rollback_count = 0
    last_draft: str | None = None
    # 수리에 실패한 변종 후보 sid. 롤백 후 관계 판단에서 이 룰들은 컨텍스트에서 빼서 같은 오판을
    # 반복하지 않게 한다 — temperature 0에서는 같은 입력이면 같은 답이 나오므로, 입력을 바꿔야
    # 롤백이 의미가 있다.
    failed_variant_sids: set[int] = set()

    while True:
        if trace.llm_calls() >= max_llm_calls:
            trace.record("outcome", result="failed", reason="llm_budget_exceeded")
            raise OrchestratorFailure(
                f"LLM 호출 예산({max_llm_calls}회) 초과 — 검증 통과 룰을 만들지 못함",
                draft_rule_text=last_draft,
            )
        existing_rules = await rule_memory.list()
        llm_context_rules = [
            r for r in existing_rules if r.origin != "imported" and r.sid not in failed_variant_sids
        ]

        if force_new:
            relation = RelationAssessOutput(
                is_variant=False, matched_sid=None, reasoning="관계 판단 우회 (롤백 상한 초과)"
            )
        else:
            relation = await assess_relation(
                llm_client, flow_summary, llm_context_rules, models.relation_assess
            )
        trace.record(
            "relation_assess", is_variant=relation.is_variant, matched_sid=relation.matched_sid,
            reasoning=relation.reasoning, forced=force_new, context_rules=len(llm_context_rules),
            excluded_sids=sorted(failed_variant_sids),
        )

        target_item: RuleItem | None = None
        if relation.is_variant and relation.matched_sid is not None:
            if relation.matched_sid in failed_variant_sids:
                target_item = None  # 이미 수리에 실패한 룰을 또 가리켰다 — 신규 취급
            else:
                try:
                    target_item = await rule_memory.get(relation.matched_sid)
                except KeyError:
                    target_item = None  # 관계 판단이 없는 sid를 가리켰다 — 신규 취급

        if target_item is not None:
            success, final_rule_text, attempts = await _repair_cycle(
                llm_client, target_item, flow_summary, verify_ctx, models, trace
            )
            last_draft = final_rule_text
            if success:
                if attempts == 0 and final_rule_text == target_item.rule_text:
                    # 기존 룰이 손대지 않은 상태로 신규 샘플까지 전부 통과했다 —
                    # 수리할 게 없다. rev를 올리거나 다시 배포하지 않고, 이 샘플을
                    # 해당 룰의 근거 이벤트로만 덧붙인다.
                    await record_covered_evidence(rule_memory, target_item.sid, repr_event_ids)
                    trace.record("outcome", result="already_covered", sid=target_item.sid, evidence_added=True)
                    raise AlreadyCovered(target_item.sid)
                item = await record_repaired_rule(
                    rule_memory, target_item.sid, final_rule_text, repr_event_ids,
                    rationale=_rationale(relation, None, blanked_fields),
                )
                trace.record("outcome", result="repaired", sid=item.sid, rev=item.rev)
                return item
        else:
            success, final_rule_text, sid, _, validated_role_group, attack_summary = await _generate_cycle(
                llm_client, flow_summary, suggested_threshold, existing_rules,
                verify_ctx, models, sid_range, role_group_hint, role_groups,
                reserved_sids or set(), trace,
            )
            last_draft = final_rule_text or last_draft
            if success:
                assert validated_role_group is not None
                item = await record_generated_rule(
                    rule_memory, sid, final_rule_text, validated_role_group,
                    repr_event_ids, repr_pcap_path,
                    rationale=_rationale(relation, attack_summary, blanked_fields),
                )
                trace.record("outcome", result="generated", sid=item.sid, role_group=item.role_group)
                return item

        if target_item is None:
            # 신규 생성 경로가 K회 수리까지 실패했다. 관계 판단으로 되돌려도 temperature 0에서는
            # 같은 "신규" 판정과 같은 후보가 나오므로 롤백은 호출만 태운다 — 여기서 끝낸다.
            # (롤백은 "변종 → 수리" 오판을 되돌리기 위한 장치다.)
            trace.record("outcome", result="failed", draft=final_rule_text,
                         reason="forced_new_failed" if force_new else "generate_failed")
            raise OrchestratorFailure(
                f"신규 생성 경로에서 K={K_MAX}회 수리 후에도 검증 실패: {final_rule_text}",
                draft_rule_text=final_rule_text,
            )

        failed_variant_sids.add(target_item.sid)
        rollback_count += 1
        trace.record("rollback", count=rollback_count, failed_variant_sid=target_item.sid)
        if rollback_count > N_MAX:
            force_new = True


async def _repair_cycle(
    llm_client: LLMClient,
    target_item: RuleItem,
    flow_summary: dict,
    verify_ctx: VerifyContext,
    models: ModelConfig,
    trace: DecisionTrace | None = None,
) -> tuple[bool, str, int]:
    """대표 샘플과 신규 샘플이 둘 다 통과해야 유효한 수리로 인정한다."""
    trace = DecisionTrace() if trace is None else trace
    rule_text = target_item.rule_text
    attack_pcaps = _dedupe(
        verify_ctx.attack_pcaps
        + ([target_item.repr_pcap_path] if target_item.repr_pcap_path else [])
    )

    history: list[dict] = []  # 이미 실패한 수리 시도 — 미탐↔오탐 사이를 오가는 것을 막는다
    for attempt in range(K_MAX + 1):
        before = rule_text
        passed, rule_text, diagnostic = _verify(
            rule_text, attack_pcaps, verify_ctx.benign_pcaps, verify_ctx.suricata_binary
        )
        _trace_verify(trace, attempt, passed, diagnostic, before, rule_text, phase="repair")
        if passed:
            return True, rule_text, attempt
        if attempt == K_MAX:
            break
        failure_type = _failure_type(diagnostic)
        calibrated = _try_threshold_calibration(
            failure_type, rule_text, attack_pcaps, verify_ctx.benign_pcaps, verify_ctx.suricata_binary, trace
        )
        if calibrated is not None:
            rule_text = set_sid_and_rev(calibrated, target_item.sid, target_item.rev + 1)
            continue  # LLM 없이 고쳤다 — 다음 루프에서 다시 검증
        trace.record("repair", failure_type=failure_type, phase="repair", sid=target_item.sid)
        repaired = await repair_rule(
            llm_client,
            rule_text,
            failure_type,
            _repair_context(failure_type, diagnostic, flow_summary,
                            contrast_pcaps=(attack_pcaps, verify_ctx.benign_pcaps, verify_ctx.suricata_binary),
                            history=history),
            models.rule_repair,
        )
        history.append({"rule_text": rule_text, "failure": failure_type})
        # 수리본의 sid는 원래 룰 그대로, rev는 다음 리비전으로 고정한다
        rule_text = set_sid_and_rev(repaired, target_item.sid, target_item.rev + 1)

    return False, rule_text, K_MAX


async def _generate_cycle(
    llm_client: LLMClient,
    flow_summary: dict,
    suggested_threshold: dict | None,
    existing_rules: list[RuleItem],
    verify_ctx: VerifyContext,
    models: ModelConfig,
    sid_range: tuple[int, int],
    role_group_hint: str,
    role_groups: dict[str, RoleGroupDef],
    reserved_sids: set[int] = frozenset(),
    trace: DecisionTrace | None = None,
) -> tuple[bool, str, int, int, str | None, str | None]:
    """(성공 여부, 최종 룰, sid, 시도 횟수, 확정된 역할 그룹, 공격 요약)을 돌려준다.

    역할 그룹 정합성 검사도 검증 루프 안에 있다 — 문법/트리거/오탐을 통과했는데
    방향이나 classtype이 그룹 정의와 안 맞는 룰은 곧바로 실패 처리하지 않고
    role_group 수리 프롬프트로 한 번 더 돌린다.
    """
    trace = DecisionTrace() if trace is None else trace
    existing_sids = {r.sid for r in existing_rules} | set(reserved_sids)
    sid = allocate_sid(existing_sids, sid_range)
    target_role_group = role_groups.get(role_group_hint)

    candidates: list[str] = []
    last_diagnostic = "no candidates generated"
    attack_summary: str | None = None
    history: list[dict] = []  # 이미 실패한 수리 시도

    for attempt in range(K_MAX + 1):
        if not candidates:
            gen_output = await generate_rules(
                llm_client, flow_summary, suggested_threshold, [sid], models.rule_generate,
                target_role_group,
            )
            candidates = gen_output.candidates
            attack_summary = gen_output.attack_summary
            trace.record("generate", candidates=len(candidates), sid=sid, attack_summary=attack_summary)

        # LLM이 지어낸 sid/rev는 믿지 않는다 — 할당된 sid와 rev:1로 고정한다
        candidates = [set_sid_and_rev(c, sid, 1) for c in candidates]

        passing: list[tuple[str, str]] = []  # (룰, 확정 역할 그룹)
        diagnostics: list[str] = []
        for candidate in candidates:
            passed, fixed_text, diagnostic = _verify(
                candidate, verify_ctx.attack_pcaps, verify_ctx.benign_pcaps, verify_ctx.suricata_binary
            )
            _trace_verify(trace, attempt, passed, diagnostic, candidate, fixed_text, phase="generate")
            if not passed:
                diagnostics.append(diagnostic)
                continue
            try:
                group = assign_role_group(fixed_text, role_group_hint, role_groups)
            except ValueError as exc:
                diagnostics.append(Diagnostic(f"role_group:{exc}"))
                trace.record("verify", attempt=attempt, passed=False, failure_kind="role_group",
                             detail=str(exc)[:300], phase="generate")
                continue
            trace.record("role_group", group=group, hint=role_group_hint)
            passing.append((fixed_text, group))

        if passing:
            if len(passing) > 1:
                trace.record("select", passing=len(passing))
            selected = await select_best_candidate(
                llm_client, [text for text, _ in passing], models.rule_select
            )
            selected_group = next(group for text, group in passing if text == selected)
            return True, selected, sid, attempt, selected_group, attack_summary

        if diagnostics:
            # 첫 후보의 진단을 기준으로 수리한다 (candidates[0]을 고치므로). 샘플도 그것을 따른다.
            last_diagnostic = Diagnostic(
                "; ".join(diagnostics), getattr(diagnostics[0], "samples", None)
            )
        if attempt == K_MAX:
            break

        failure_type = _failure_type(diagnostics[0] if diagnostics else last_diagnostic)
        calibrated = _try_threshold_calibration(
            failure_type, candidates[0], verify_ctx.attack_pcaps, verify_ctx.benign_pcaps,
            verify_ctx.suricata_binary, trace,
        )
        if calibrated is not None:
            candidates = [calibrated]
            continue  # LLM 없이 고쳤다 — 다음 루프에서 다시 검증
        trace.record("repair", failure_type=failure_type, phase="generate", sid=sid)
        context = _repair_context(
            failure_type, last_diagnostic, flow_summary,
            contrast_pcaps=(verify_ctx.attack_pcaps, verify_ctx.benign_pcaps, verify_ctx.suricata_binary),
            history=history,
        )
        history.append({"rule_text": candidates[0], "failure": failure_type})
        if failure_type == "role_group":
            context["role_group_reasons"] = str(last_diagnostic)
            context["target_role_group"] = (
                target_role_group.model_dump() if target_role_group else None
            )
        repaired = await repair_rule(
            llm_client, candidates[0], failure_type, context, models.rule_repair
        )
        candidates = [repaired]

    return False, candidates[0] if candidates else "", sid, K_MAX, None, attack_summary


def _verify(
    rule_text: str, attack_pcaps: list[str], benign_pcaps: list[str], suricata_binary: str
) -> tuple[bool, str, str]:
    fixed = apply_deterministic_fixes(rule_text)
    rule_text = fixed.rule_text

    # 정책 게이트: drop/reject는 결정적 리라이트가 alert로 바꿔놨고, 그래도
    # alert가 아니면(pass 등) 검증 자체를 거부한다 — IDS 모드 원칙(§3, §14).
    action = extract_action(rule_text)
    if action != "alert":
        return False, rule_text, f"policy:action must be alert, got {action!r}"

    syntax = check_rule_syntax(rule_text, suricata_binary)
    if not syntax.ok:
        return False, rule_text, Diagnostic(f"syntax:{syntax.raw_output}")

    attack_result = replay_rule(rule_text, "attack", attack_pcaps, suricata_binary)
    if not attack_result.ok:
        return False, rule_text, Diagnostic(f"no_trigger:{attack_result.raw_output}")

    benign_result = replay_rule(rule_text, "benign", benign_pcaps, suricata_binary)
    if not benign_result.ok:
        return (
            False,
            rule_text,
            Diagnostic(
                f"false_positive:sids={benign_result.triggered_sids}:{benign_result.raw_output}",
                benign_result.alert_samples,
            ),
        )

    return True, rule_text, "ok"


def _try_threshold_calibration(
    failure_type: FailureType, rule_text: str, attack_pcaps: list[str], negative_pcaps: list[str],
    suricata_binary: str, trace: DecisionTrace,
) -> str | None:
    """rate 룰의 오탐/미탐을 LLM 대신 재생 탐색으로 고쳐본다. 성공하면 새 룰 텍스트.

    - 오탐: 먼저 같은 창에서 count만 올린다(calibrate_threshold). 안 되면 창까지 바꿔 분리 탐색.
    - 미탐: 창까지 바꿔 분리 탐색(find_separating_threshold). count 1로도 안 울리면 매칭 조건 문제라 LLM에 넘긴다.
    """
    if failure_type not in ("false_positive", "no_trigger"):
        return None
    if failure_type == "no_trigger" and extract_threshold_count(rule_text) is None:
        return None  # rate 룰이 아닌 미탐은 매칭 조건 문제 — 조용히 LLM 수리로 넘긴다
    if failure_type == "false_positive":
        result = calibrate_threshold(rule_text, attack_pcaps, negative_pcaps, suricata_binary)
        if result is not None and result.changed:
            trace.record("threshold_calibration", ok=True, mode="raise_count", from_count=result.original_count,
                         to_count=result.calibrated_count, replays=result.replays)
            logger.info("threshold calibrated by replay: count %d -> %d",
                        result.original_count, result.calibrated_count)
            return result.rule_text
    separation = find_separating_threshold(rule_text, attack_pcaps, negative_pcaps, suricata_binary)
    if separation is None:
        trace.record("threshold_calibration", ok=False, failure_type=failure_type,
                     reason="not a rate rule" if "count" not in rule_text else "no separating count/window")
        return None
    trace.record("threshold_calibration", ok=True, mode="separate", failure_type=failure_type,
                 from_count=separation.original_count, from_seconds=separation.original_seconds,
                 to_count=separation.count, to_seconds=separation.seconds,
                 attack_max=separation.attack_max, negative_max=separation.negative_max,
                 replays=separation.replays)
    logger.info("threshold separated by replay: %d/%ds -> %d/%ds (attack max %d, negative max %d)",
                separation.original_count, separation.original_seconds, separation.count, separation.seconds,
                separation.attack_max, separation.negative_max)
    return separation.rule_text


def _trace_verify(
    trace: DecisionTrace, attempt: int, passed: bool, diagnostic: str, before: str, after: str, phase: str
) -> None:
    fixes = apply_deterministic_fixes(before).applied_fixes if before != after else []
    trace.record(
        "verify", attempt=attempt, passed=passed, phase=phase,
        failure_kind=None if passed else _failure_type(diagnostic),
        detail=None if passed else str(diagnostic)[:300],
        applied_fixes=fixes,
        rule=after[:400],  # 어떤 시도가 어떻게 실패했는지 사후 분석용 (룰 텍스트는 LLM 출력이라 공격자 문자열 아님)
    )


def _failure_type(diagnostic: str) -> FailureType:
    prefix = str(diagnostic).split(":", 1)[0]
    if prefix in ("syntax", "no_trigger", "false_positive", "role_group"):
        return prefix  # type: ignore[return-value]
    return "syntax"  # policy 위반 등은 문법 수리 프롬프트로 보낸다


def _suricata_errors_only(raw_output: str) -> str:
    """suricata 출력에서 에러/경고 줄만 남기고 길이를 제한한다 — 정보성 로그는 수리에 도움이 안 된다."""
    lines = [
        line for line in raw_output.splitlines()
        if line.startswith(("E:", "W:", "Error", "error")) or "rror" in line[:40]
    ]
    text = "\n".join(lines) if lines else raw_output
    return text[-_MAX_RAW_OUTPUT_CHARS:]


def _repair_context(
    failure_type: FailureType,
    diagnostic: str,
    flow_summary: dict,
    contrast_pcaps: tuple[list[str], list[str], str] | None = None,
    history: list[dict] | None = None,
) -> dict:
    """실패 유형별 수리 프롬프트가 기대하는 입력 필드를 채운다 (rule_repair.py 프롬프트 참조).

    - syntax: 에러 KB(error_kb)에서 에러 클래스와 수리 지침을 찾아 error_guidance로 넘긴다.
    - no_trigger: 리플레이 출력 요약(replay_output).
    - false_positive: 오탐을 낸 정상 플로우 샘플(benign_flow)과 잡아야 하는 악성 플로우(malicious_flow).
    - no_trigger/false_positive: 공격·negative pcap의 수치 프로파일 대조(traffic_contrast). threshold 룰을
      고칠 때 count/seconds를 어디에 둬야 둘이 갈리는지, 혹은 수치로는 안 갈려서 다른 신호(RST, 404)가
      필요한지 근거가 된다. Suricata가 계산한 숫자뿐이라 공격자 문자열이 섞이지 않는다.
    - previous_attempts: 같은 사이클에서 이미 실패한 룰과 실패 유형 (최근 3개).
    모든 값은 데이터로만 전달된다 — 프롬프트는 이것들을 지시로 취급하지 말라고 명시한다.
    """
    text = str(diagnostic)
    detail = text.split(":", 1)[1] if ":" in text else text
    context: dict = {"target_flow": flow_summary, "diagnostic": text[:_MAX_RAW_OUTPUT_CHARS]}

    if failure_type == "syntax":
        error_class = classify_error(detail)
        context["error_guidance"] = (
            {"error_class": error_class.name, "guidance": error_class.repair_guidance}
            if error_class else None
        )
        context["parser_errors"] = _suricata_errors_only(detail)
    elif failure_type == "no_trigger":
        context["replay_output"] = _suricata_errors_only(detail)
    elif failure_type == "false_positive":
        context["benign_flow"] = getattr(diagnostic, "samples", []) or []
        context["malicious_flow"] = flow_summary
    if contrast_pcaps is not None and failure_type in ("no_trigger", "false_positive"):
        attack, negatives, binary = contrast_pcaps
        try:
            context["traffic_contrast"] = traffic_contrast(list(attack), list(negatives), binary)
        except Exception as exc:  # noqa: BLE001 - 프로파일은 보조 근거라 실패해도 수리는 진행한다
            logger.warning("traffic contrast unavailable: %s", exc)
    if history:
        context["previous_attempts"] = history[-3:]
    return context


def _dedupe(paths: list[str]) -> list[str]:
    return list(dict.fromkeys(paths))


def _rationale(
    relation: RelationAssessOutput, attack_summary: str | None, blanked_fields: list[str]
) -> str:
    """사람이 읽는 판단 근거. PR/제안서 본문 전용 — 파이프라인 입력으로 쓰지 않는다."""
    parts = [f"관계 판단: {'기존 룰의 변종' if relation.is_variant else '신규 유형'} — {relation.reasoning}"]
    if attack_summary:
        parts.append(f"공격 요약: {attack_summary}")
    if blanked_fields:
        parts.append(
            "인젝션 필터가 LLM 입력에서 비운 필드: " + ", ".join(blanked_fields)
            + " (해당 값은 공격자 통제 문자열로 판정돼 판단에 반영되지 않았음)"
        )
    return "\n".join(parts)


def _check_already_covered(
    existing_rules: list[RuleItem], sample_pcap: str, suricata_binary: str
) -> int | None:
    """현재 룰셋 전체를 샘플 pcap에 재생해 이미 알럿이 발생하는지 확인한다."""
    if not existing_rules:
        return None

    combined_rules = "\n".join(item.rule_text for item in existing_rules)
    result = replay_rule(combined_rules, "attack", [sample_pcap], suricata_binary)
    if not result.triggered_sids:
        return None
    return result.triggered_sids[0]
