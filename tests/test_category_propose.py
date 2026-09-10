"""propose_category()가 미분류 실패 컨텍스트를 실제로 LLM에 전달하는지 검증한다."""

import pytest

from meerkat.agent.category_propose import propose_category
from meerkat.agent.schemas import CategoryProposalOutput


class _CapturingLLMClient:
    def __init__(self, output: CategoryProposalOutput):
        self._output = output
        self.captured_user_content: dict = {}

    async def complete_structured(self, system_prompt, user_content, output_schema, model, temperature=0.0):
        self.captured_user_content = user_content
        return self._output


@pytest.mark.asyncio
async def test_propose_category_passes_failure_context_to_llm():
    output = CategoryProposalOutput(
        candidate_category_name="ssh-bruteforce",
        protocols=["tcp"],
        classtypes=["attempted-admin"],
        direction="inbound",
        expected_keywords=["threshold"],
        reasoning="SSH 포트에 반복적인 연결 시도",
    )
    llm = _CapturingLLMClient(output)

    result = await propose_category(
        llm,
        flow_summary={"src_ip": "10.0.0.77", "dest_port": 22},
        failure_reason="no role group matches this rule",
        draft_rule_text='alert tcp any any -> any 22 (classtype:attempted-admin; sid:1000000; rev:1;)',
        model="fake",
    )

    assert result == output
    assert llm.captured_user_content["flow_summary"] == {"src_ip": "10.0.0.77", "dest_port": 22}
    assert llm.captured_user_content["failure_reason"] == "no role group matches this rule"
    assert "attempted-admin" in llm.captured_user_content["draft_rule_text"]


@pytest.mark.asyncio
async def test_propose_category_handles_missing_draft_rule():
    output = CategoryProposalOutput(
        candidate_category_name="dns-tunneling",
        protocols=["udp"],
        classtypes=["policy-violation"],
        direction="outbound",
        reasoning="비정상적으로 긴 DNS 쿼리명 반복",
    )
    llm = _CapturingLLMClient(output)

    result = await propose_category(
        llm,
        flow_summary={"src_ip": "10.0.0.5"},
        failure_reason="verification never passed",
        draft_rule_text=None,
        model="fake",
    )

    assert result == output
    assert llm.captured_user_content["draft_rule_text"] is None


def test_category_proposal_output_lowercases_protocols():
    """Claude가 protocols를 ["ICMP", "TLS"]처럼 대문자로 낼 때가 있는데,
    _protocol_matches는 소문자로 비교하므로 여기서 강제로 소문자화해야 한다."""
    output = CategoryProposalOutput(
        candidate_category_name="tls-c2-beaconing",
        protocols=["TCP", "TLS"],
        classtypes=["trojan-activity"],
        direction="outbound",
        reasoning="주기적인 SNI 비콘",
    )
    assert output.protocols == ["tcp", "tls"]
