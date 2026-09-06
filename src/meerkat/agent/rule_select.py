from meerkat.agent.schemas import RuleSelectOutput
from meerkat.llm.client import LLMClient

SYSTEM_PROMPT = """검증을 통과한 Suricata 룰 후보가 여러 개 있다. 그중 가장 나은 \
하나를 골라라.

기준:
- 더 짧고 구체적인 content 매칭을 우선한다.
- 불필요하게 넓은 조건(과도한 헤더 검사, 느슨한 PCRE)이 적은 쪽을 우선한다.
- 단일 이슈만 타겟하는 쪽을 우선한다.

reason은 사람이 읽는 용도이며 다음 단계 입력이 되지 않는다."""


async def select_best_candidate(
    llm_client: LLMClient,
    passing_candidates: list[str],
    model: str,
) -> str:
    """후보가 하나면 LLM 호출 없이 반환한다. 둘 이상이면 LLM이 최종 선택한다."""
    if len(passing_candidates) == 1:
        return passing_candidates[0]

    user_content = {"candidates": passing_candidates}
    output: RuleSelectOutput = await llm_client.complete_structured(
        system_prompt=SYSTEM_PROMPT,
        user_content=user_content,
        output_schema=RuleSelectOutput,
        model=model,
        temperature=0.0,
    )

    if 0 <= output.selected_index < len(passing_candidates):
        return passing_candidates[output.selected_index]
    return passing_candidates[0]
