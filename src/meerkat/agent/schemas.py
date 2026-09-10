from pydantic import BaseModel, field_validator


class RelationAssessOutput(BaseModel):
    is_variant: bool
    matched_sid: int | None
    reasoning: str


class RuleGenerateOutput(BaseModel):
    candidates: list[str]  #LLM이 뽑은 후보 룰 여러 개
    attack_summary: str


class RuleSelectOutput(BaseModel):
    selected_index: int
    reason: str


class RuleRepairOutput(BaseModel):
    repaired_rule_text: str


class CategoryProposalOutput(BaseModel):
    candidate_category_name: str
    protocols: list[str]
    classtypes: list[str]
    direction: str
    expected_keywords: list[str] = []
    reasoning: str

    @field_validator("protocols", mode="after")
    @classmethod
    def _normalize_protocol_case(cls, value: list[str]) -> list[str]:
        # role_groups.yaml/_protocol_matches는 소문자 기준으로 비교한다 —
        # LLM이 "ICMP"/"TLS"처럼 대문자로 낼 때가 있어 여기서 강제로 맞춘다.
        return [p.lower() for p in value]
