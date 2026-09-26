"""rules/*.rules → rule_memory 동기화."""

import datetime
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("scripts").resolve()))
from sync_rules_to_memory import sync  # noqa: E402

from meerkat.storage.rule_memory import RuleItem, RuleMemory  # noqa: E402

RULE_A = 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"a"; classtype:attempted-recon; sid:1000001; rev:1;)'
RULE_B = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"b"; http.uri; content:"/x"; classtype:web-application-attack; sid:1000002; rev:3;)'


@pytest.mark.asyncio
async def test_new_file_rules_are_added_as_manual_and_existing_ones_updated(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "scanning.rules").write_text(f"# comment\n{RULE_A}\n")
    (rules_dir / "web-attack.rules").write_text(RULE_B + "\n")

    memory = RuleMemory(path=tmp_path / "m.json")
    now = datetime.datetime.now(datetime.timezone.utc)
    await memory.upsert(RuleItem(  # 메모리에 옛 버전이 있는 룰 — 파일을 따라가야 한다
        sid=1000002, rev=2, rule_text=RULE_B.replace("rev:3", "rev:2").replace("/x", "/old"),
        role_group="web-attack", repr_event_ids=["e"], repr_pcap_path=None, created_at=now, updated_at=now,
        origin="generated",
    ))

    stats = await sync(str(rules_dir), str(tmp_path / "m.json"))
    assert stats == {"seen": 2, "added": 1, "updated": 1, "unchanged": 0, "skipped_no_sid": 0}

    a = await memory.get(1000001)
    assert a.origin == "manual" and a.role_group == "scanning" and a.rule_text == RULE_A
    b = await memory.get(1000002)
    assert b.origin == "generated" and b.rev == 3 and "/x" in b.rule_text and b.repr_event_ids == ["e"]

    again = await sync(str(rules_dir), str(tmp_path / "m.json"))
    assert again["unchanged"] == 2 and again["added"] == 0


@pytest.mark.asyncio
async def test_dry_run_changes_nothing(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "scanning.rules").write_text(RULE_A + "\n")
    stats = await sync(str(rules_dir), str(tmp_path / "m.json"), dry_run=True)
    assert stats["added"] == 1
    assert await RuleMemory(path=tmp_path / "m.json").list() == []


@pytest.mark.asyncio
async def test_manual_rules_enter_llm_context_but_imported_do_not(tmp_path):
    """origin=manual은 관계 판단 LLM 컨텍스트에 들어가고 imported는 빠져야 한다."""
    from conftest import FakeLLMClient

    from meerkat.agent.orchestrator import ModelConfig, VerifyContext, orchestrate
    from meerkat.agent.schemas import RelationAssessOutput, RuleGenerateOutput

    memory = RuleMemory(path=tmp_path / "m.json")
    now = datetime.datetime.now(datetime.timezone.utc)
    for sid, origin in ((1000001, "manual"), (2000001, "imported")):
        await memory.upsert(RuleItem(sid=sid, rev=1, rule_text=f"alert tcp any any -> any any (sid:{sid}; rev:1;)",
                                     role_group="scanning", repr_event_ids=[], repr_pcap_path=None,
                                     created_at=now, updated_at=now, origin=origin))

    captured: dict = {}

    class Capturing(FakeLLMClient):
        async def complete_structured(self, system_prompt, user_content, output_schema, model, temperature=0.0):
            if output_schema is RelationAssessOutput:
                captured.update(user_content)
            return await super().complete_structured(system_prompt, user_content, output_schema, model, temperature)

    import meerkat.agent.orchestrator as orch

    llm = Capturing()
    llm.queue(RelationAssessOutput(is_variant=False, matched_sid=None, reasoning="x"))
    llm.queue(RuleGenerateOutput(candidates=[
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"n"; threshold:type threshold, track by_src, count 1, seconds 1; classtype:attempted-recon; sid:1; rev:1;)'
    ], attack_summary="x"))
    orch_verify = orch._verify
    orch._verify = lambda r, a, b, s: (True, r, "ok")
    try:
        await orchestrate(flow_summary={"src_ip": "1.1.1.1"}, repr_event_ids=[], repr_pcap_path=None,
                          role_group_hint="scanning", llm_client=llm, rule_memory=memory,
                          models=ModelConfig("f", "f", "f", "f"), verify_ctx=VerifyContext([], []))
    finally:
        orch._verify = orch_verify
    sids = [r["sid"] for r in captured["existing_rules"]]
    assert sids == [1000001]
