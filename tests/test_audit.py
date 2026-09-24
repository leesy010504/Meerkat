"""의사결정 감사 로그가 오케스트레이터의 판단 단계를 순서대로 담는지 검증한다."""

import json

import pytest
from conftest import FakeLLMClient

from meerkat.agent.audit import DecisionTrace
from meerkat.agent.orchestrator import (
    AlreadyCovered,
    ModelConfig,
    VerifyContext,
    orchestrate,
)
from meerkat.agent.schemas import (
    RelationAssessOutput,
    RuleGenerateOutput,
    RuleRepairOutput,
)
from meerkat.storage.rule_memory import RuleMemory

MODELS = ModelConfig(relation_assess="fake", rule_generate="fake", rule_repair="fake", rule_select="fake")
GOOD = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ok"; threshold:type threshold, track by_src, '
    "count 1, seconds 1; classtype:attempted-recon; sid:1000000; rev:1;)"
)


def _fail_then_pass(monkeypatch, fails: int):
    import meerkat.agent.orchestrator as orch

    state = {"n": 0}

    def fake_verify(rule_text, attack_pcaps, benign_pcaps, suricata_binary):
        state["n"] += 1
        if state["n"] <= fails:
            return False, rule_text, "no_trigger:stub"
        return True, rule_text, "ok"

    monkeypatch.setattr(orch, "_verify", fake_verify)


@pytest.mark.asyncio
async def test_trace_records_generate_verify_repair_and_outcome(monkeypatch, tmp_path):
    _fail_then_pass(monkeypatch, fails=1)
    llm = FakeLLMClient()
    llm.queue(RelationAssessOutput(is_variant=False, matched_sid=None, reasoning="새 유형"))
    llm.queue(RuleGenerateOutput(candidates=["drop tcp any any -> any any (sid:1;)"], attack_summary="스캔"))
    llm.queue(RuleRepairOutput(repaired_rule_text=GOOD))

    trace = DecisionTrace(context={"metric": "unique_dst_ports_per_src", "src_ip": "10.0.0.9"})
    item = await orchestrate(
        flow_summary={"src_ip": "10.0.0.9"}, repr_event_ids=["e1"], repr_pcap_path=None,
        role_group_hint="scanning", llm_client=llm, rule_memory=RuleMemory(path=tmp_path / "m.json"),
        models=MODELS, verify_ctx=VerifyContext(attack_pcaps=[], benign_pcaps=[]), trace=trace,
    )

    kinds = [e["event"] for e in trace.events]
    assert kinds == [
        "injection_filter", "relation_assess", "generate", "verify", "repair", "verify", "role_group", "outcome",
    ]
    assert trace.events[3]["failure_kind"] == "no_trigger"
    assert trace.events[4]["failure_type"] == "no_trigger"
    assert trace.outcome() == "generated" and trace.events[-1]["sid"] == item.sid
    assert trace.llm_calls() == 3 and trace.repair_types() == {"no_trigger": 1}

    record = trace.to_record()
    assert record["context"]["src_ip"] == "10.0.0.9" and record["verify_runs"] == 2

    path = trace.append_jsonl(tmp_path / "audit" / "decisions.jsonl")
    lines = path.read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["outcome"] == "generated"

    summary = "\n".join(trace.summary_lines())
    assert "관계 판단: 신규 유형" in summary and "LLM 수리 (no_trigger)" in summary
    assert "결과: generated" in summary


@pytest.mark.asyncio
async def test_trace_records_already_covered_short_circuit(tmp_path):
    import datetime

    from meerkat.storage.rule_memory import RuleItem

    memory = RuleMemory(path=tmp_path / "m.json")
    now = datetime.datetime.now(datetime.timezone.utc)
    await memory.upsert(RuleItem(
        sid=1000001, rev=1, role_group="scanning", repr_event_ids=[], repr_pcap_path=None,
        created_at=now, updated_at=now, origin="generated",
        rule_text=(
            'alert tcp any any -> any any (msg:"scan"; flow:to_server; threshold:type threshold, track by_src, '
            "count 70, seconds 60; classtype:attempted-recon; sid:1000001; rev:1;)"
        ),
    ))
    trace = DecisionTrace()
    with pytest.raises(AlreadyCovered):
        await orchestrate(
            flow_summary={"src_ip": "1.2.3.4"}, repr_event_ids=["e1"], repr_pcap_path="pcaps/attack/port_scan.pcap",
            role_group_hint="scanning", llm_client=FakeLLMClient(), rule_memory=memory, models=MODELS,
            verify_ctx=VerifyContext(attack_pcaps=[], benign_pcaps=[]), trace=trace,
        )
    kinds = [e["event"] for e in trace.events]
    assert kinds == ["injection_filter", "already_covered_check", "outcome"]
    assert trace.events[1]["covering_sid"] == 1000001 and trace.llm_calls() == 0
    assert "sid 1000001가 이미 탐지" in "\n".join(trace.summary_lines())
