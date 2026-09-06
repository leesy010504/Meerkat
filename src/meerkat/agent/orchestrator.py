from dataclasses import dataclass
from typing import Literal

from meerkat.agent.memory_update import record_generated_rule, record_repaired_rule
from meerkat.agent.relation_assess import assess_relation
from meerkat.agent.rule_generate import generate_rules
from meerkat.agent.rule_repair import FailureType, repair_rule
from meerkat.agent.rule_select import select_best_candidate
from meerkat.agent.schemas import RelationAssessOutput
from meerkat.llm.client import LLMClient
from meerkat.mcp_server.tools.deploy import assign_role_group
from meerkat.mcp_server.tools.rule_ops import allocate_sid
from meerkat.security.injection_filter import filter_flow_fields
from meerkat.storage.rule_memory import RuleItem, RuleMemory
from meerkat.validation.deterministic_fix import apply_deterministic_fixes
from meerkat.validation.logic_check import load_role_groups
from meerkat.validation.replay import replay_rule
from meerkat.validation.syntax import check_rule_syntax

K_MAX = 3  # 룰 하나당 수리 재시도 횟수
N_MAX = 2  # 롤백 반복 상한


class OrchestratorFailure(Exception):
    pass


class AlreadyCovered(Exception):
    """현재 룰셋이 이미 이 트래픽을 탐지하고 있음을 나타낸다."""

    def __init__(self, matched_sid: int):
        self.matched_sid = matched_sid
        super().__init__(f"traffic already covered by existing rule sid={matched_sid}")


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
) -> RuleItem:
    # 진입점에서 한 번만 인젝션 필터를 적용한다
    flow_summary = filter_flow_fields(flow_summary)
    role_groups = load_role_groups(role_groups_path)

    # 현재 룰셋으로 이미 탐지되는지 먼저 확인한다
    if repr_pcap_path is not None:
        existing_rules = await rule_memory.list()
        covering_sid = _check_already_covered(
            existing_rules, repr_pcap_path, verify_ctx.suricata_binary
        )
        if covering_sid is not None:
            raise AlreadyCovered(covering_sid)

    force_new = False
    rollback_count = 0

    while True:
        existing_rules = await rule_memory.list()
        llm_context_rules = [r for r in existing_rules if r.origin != "imported"]

        if force_new:
            relation = RelationAssessOutput(
                is_variant=False, matched_sid=None, reasoning="관계 판단 우회 (롤백 상한 초과)"
            )
        else:
            relation = await assess_relation(
                llm_client, flow_summary, llm_context_rules, models.relation_assess
            )

        target_item: RuleItem | None = None
        if relation.is_variant and relation.matched_sid is not None:
            try:
                target_item = await rule_memory.get(relation.matched_sid)
            except KeyError:
                target_item = None  # 관계 판단이 없는 sid를 가리켰다 — 신규 취급

        if target_item is not None:
            success, final_rule_text, _ = await _repair_cycle(
                llm_client, target_item, flow_summary, verify_ctx, models
            )
            if success:
                return await record_repaired_rule(
                    rule_memory, target_item.sid, final_rule_text, repr_event_ids
                )
        else:
            success, final_rule_text, sid, _ = await _generate_cycle(
                llm_client, flow_summary, suggested_threshold, existing_rules,
                verify_ctx, models, sid_range,
            )
            if success:
                try:
                    validated_role_group = assign_role_group(
                        final_rule_text, role_group_hint, role_groups
                    )
                except ValueError as exc:
                    raise OrchestratorFailure(f"역할 그룹 결정 실패: {exc}") from exc
                return await record_generated_rule(
                    rule_memory, sid, final_rule_text, validated_role_group,
                    repr_event_ids, repr_pcap_path,
                )

        if force_new:
            raise OrchestratorFailure(
                f"신규 생성 강제 후에도 K={K_MAX}회 수리 실패: {final_rule_text}"
            )

        rollback_count += 1
        if rollback_count > N_MAX:
            force_new = True


async def _repair_cycle(
    llm_client: LLMClient,
    target_item: RuleItem,
    flow_summary: dict,
    verify_ctx: VerifyContext,
    models: ModelConfig,
) -> tuple[bool, str, int]:
    """대표 샘플과 신규 샘플이 둘 다 통과해야 유효한 수리로 인정한다."""
    rule_text = target_item.rule_text
    attack_pcaps = _dedupe(
        verify_ctx.attack_pcaps
        + ([target_item.repr_pcap_path] if target_item.repr_pcap_path else [])
    )

    for attempt in range(K_MAX + 1):
        passed, rule_text, diagnostic = _verify(
            rule_text, attack_pcaps, verify_ctx.benign_pcaps, verify_ctx.suricata_binary
        )
        if passed:
            return True, rule_text, attempt
        if attempt == K_MAX:
            break
        rule_text = await repair_rule(
            llm_client,
            rule_text,
            _failure_type(diagnostic),
            {"target_flow": flow_summary, "diagnostic": diagnostic},
            models.rule_repair,
        )

    return False, rule_text, K_MAX


async def _generate_cycle(
    llm_client: LLMClient,
    flow_summary: dict,
    suggested_threshold: dict | None,
    existing_rules: list[RuleItem],
    verify_ctx: VerifyContext,
    models: ModelConfig,
    sid_range: tuple[int, int],
) -> tuple[bool, str, int, int]:
    existing_sids = {r.sid for r in existing_rules}
    sid = allocate_sid(existing_sids, sid_range)

    candidates: list[str] = []
    last_diagnostic = "no candidates generated"

    for attempt in range(K_MAX + 1):
        if not candidates:
            gen_output = await generate_rules(
                llm_client, flow_summary, suggested_threshold, [sid], models.rule_generate
            )
            candidates = gen_output.candidates

        passing: list[str] = []
        diagnostics: list[str] = []
        for candidate in candidates:
            passed, fixed_text, diagnostic = _verify(
                candidate, verify_ctx.attack_pcaps, verify_ctx.benign_pcaps, verify_ctx.suricata_binary
            )
            if passed:
                passing.append(fixed_text)
            else:
                diagnostics.append(diagnostic)

        if passing:
            selected = await select_best_candidate(llm_client, passing, models.rule_select)
            return True, selected, sid, attempt

        last_diagnostic = "; ".join(diagnostics) if diagnostics else last_diagnostic
        if attempt == K_MAX:
            break

        repaired = await repair_rule(
            llm_client,
            candidates[0],
            _failure_type(last_diagnostic),
            {"target_flow": flow_summary, "diagnostic": last_diagnostic},
            models.rule_repair,
        )
        candidates = [repaired]

    return False, candidates[0] if candidates else "", sid, K_MAX


def _verify(
    rule_text: str, attack_pcaps: list[str], benign_pcaps: list[str], suricata_binary: str
) -> tuple[bool, str, str]:
    fixed = apply_deterministic_fixes(rule_text)
    rule_text = fixed.rule_text

    syntax = check_rule_syntax(rule_text, suricata_binary)
    if not syntax.ok:
        return False, rule_text, f"syntax:{syntax.raw_output}"

    attack_result = replay_rule(rule_text, "attack", attack_pcaps, suricata_binary)
    if not attack_result.ok:
        return False, rule_text, f"no_trigger:{attack_result.raw_output}"

    benign_result = replay_rule(rule_text, "benign", benign_pcaps, suricata_binary)
    if not benign_result.ok:
        return (
            False,
            rule_text,
            f"false_positive:sids={benign_result.triggered_sids}:{benign_result.raw_output}",
        )

    return True, rule_text, "ok"


def _failure_type(diagnostic: str) -> FailureType:
    prefix = diagnostic.split(":", 1)[0]
    if prefix in ("syntax", "no_trigger", "false_positive"):
        return prefix  # type: ignore[return-value]
    return "syntax"


def _dedupe(paths: list[str]) -> list[str]:
    return list(dict.fromkeys(paths))


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
