"""generate_rules()가 target_role_group을 실제로 LLM에 전달하는지 검증한다."""

import pytest

from meerkat.agent.rule_generate import generate_rules
from meerkat.agent.schemas import RuleGenerateOutput
from meerkat.validation.logic_check import RoleGroupDef


class _CapturingLLMClient:
    def __init__(self):
        self.captured_user_content: dict = {}

    async def complete_structured(self, system_prompt, user_content, output_schema, model, temperature=0.0):
        self.captured_user_content = user_content
        return RuleGenerateOutput(candidates=["alert tcp any any -> any any (sid:1000001; rev:1;)"], attack_summary="x")


@pytest.mark.asyncio
async def test_target_role_group_included_when_given():
    llm = _CapturingLLMClient()
    role_group = RoleGroupDef(
        protocols=["udp"], direction="inbound",
        expected_keywords=["threshold"], classtypes=["denial-of-service"],
    )

    await generate_rules(llm, {"src_ip": "1.2.3.4"}, None, [1000001], "fake", role_group)

    assert llm.captured_user_content["target_role_group"] == role_group.model_dump()


@pytest.mark.asyncio
async def test_target_role_group_is_none_when_not_given():
    llm = _CapturingLLMClient()

    await generate_rules(llm, {"src_ip": "1.2.3.4"}, None, [1000001], "fake")

    assert llm.captured_user_content["target_role_group"] is None
