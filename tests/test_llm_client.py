"""GeminiLLMClient의 구조화 출력을 실제 API 호출로 검증한다.
GEMINI_API_KEY가 없으면 스킵한다."""

import os

import pytest
from pydantic import BaseModel

from meerkat.llm.client import GeminiLLMClient, SchemaViolationError

pytestmark = pytest.mark.skipif(
    not os.environ.get("GEMINI_API_KEY"), reason="GEMINI_API_KEY not set"
)


class Sentiment(BaseModel):
    label: str
    confidence: float


@pytest.mark.asyncio
async def test_gemini_structured_output_roundtrip():
    client = GeminiLLMClient(api_key=os.environ["GEMINI_API_KEY"])
    result = await client.complete_structured(
        system_prompt="입력 문장의 감정을 분류해라. label은 positive/negative/neutral 중 하나.",
        user_content={"text": "오늘 정말 좋은 하루였어!"},
        output_schema=Sentiment,
        model="gemini-3.6-flash",
        temperature=0.0,
    )
    assert isinstance(result, Sentiment)
    assert result.label in ("positive", "negative", "neutral")
    assert 0.0 <= result.confidence <= 1.0


@pytest.mark.asyncio
async def test_gemini_relation_assess_schema():
    """RelationAssessOutput 스키마로도 구조화 출력이 되는지 확인."""
    from meerkat.agent.schemas import RelationAssessOutput

    client = GeminiLLMClient(api_key=os.environ["GEMINI_API_KEY"])
    result = await client.complete_structured(
        system_prompt=(
            "너는 신규 공격 샘플이 기존 룰의 변종인지 판단하는 보안 분석가다. "
            "existing_rules가 비어 있으면 무조건 신규(is_variant=false)로 판단해라."
        ),
        user_content={
            "new_sample": {"src_ip": "1.2.3.4", "dest_port": 22, "signature": "ssh brute force"},
            "existing_rules": [],
        },
        output_schema=RelationAssessOutput,
        model="gemini-3.6-flash",
        temperature=0.0,
    )
    assert isinstance(result, RelationAssessOutput)
    assert result.is_variant is False
    assert result.matched_sid is None
