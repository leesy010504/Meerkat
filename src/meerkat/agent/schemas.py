from pydantic import BaseModel


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
