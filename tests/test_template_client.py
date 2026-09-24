"""템플릿 LLM 클라이언트로 LLM 없이 오케스트레이터 전체를 끝까지 돌릴 수 있는지 확인한다."""

import pytest

from meerkat.agent.orchestrator import ModelConfig, VerifyContext, orchestrate
from meerkat.agent.schemas import RuleGenerateOutput
from meerkat.llm.client import create_llm_client
from meerkat.llm.template_client import TemplateLLMClient
from meerkat.storage.rule_memory import RuleMemory

MODELS = ModelConfig(relation_assess="t", rule_generate="t", rule_repair="t", rule_select="t")


def test_factory_returns_template_client():
    assert isinstance(create_llm_client("template"), TemplateLLMClient)


@pytest.mark.asyncio
async def test_template_uses_suggested_threshold_verbatim():
    client = TemplateLLMClient()
    out = await client.complete_structured(
        "s", {"flow_summary": {"metric": "unique_dst_ports_per_src"}, "available_sids": [1000042],
              "suggested_threshold": {"count": 73, "seconds": 300}}, RuleGenerateOutput, model="t",
    )
    assert out.candidates[0].startswith("alert tcp $EXTERNAL_NET any -> $HOME_NET any")
    assert "count 73, seconds 300" in out.candidates[0] and "sid:1000042;" in out.candidates[0]


@pytest.mark.asyncio
async def test_template_provider_produces_verified_port_scan_rule_against_real_pcaps(tmp_path):
    """실제 suricata 검증(공격 pcap 트리거 + 정상 pcap 무알럿 + 역할 그룹)까지 통과해야 한다."""
    client = TemplateLLMClient()
    item = await orchestrate(
        flow_summary={"metric": "unique_dst_ports_per_src", "src_ip": "127.0.0.1", "observed_value": 1000},
        repr_event_ids=["e1"], repr_pcap_path=None, role_group_hint="scanning",
        llm_client=client, rule_memory=RuleMemory(path=tmp_path / "m.json"), models=MODELS,
        verify_ctx=VerifyContext(
            attack_pcaps=["pcaps/attack/port_scan.pcap"],
            benign_pcaps=["pcaps/benign/web_browsing.pcap", "pcaps/benign/ssh_normal.pcap",
                          "pcaps/benign/normal_traffic.pcap"],
        ),
        suggested_threshold={"count": 60, "seconds": 300},
    )
    from meerkat.validation.threshold_calibrate import extract_threshold_count

    assert item.role_group == "scanning" and item.origin == "generated"
    # baseline count 60은 그대로 쓰되, 정상 코퍼스에 걸리면 재생 보정으로 올라갈 수 있다 — 내려가지는 않는다
    assert extract_threshold_count(item.rule_text) >= 60 and "seconds 300" in item.rule_text
    assert "RuleRepairOutput" not in client.calls  # LLM 수리 없이 통과 (보정은 결정적)
