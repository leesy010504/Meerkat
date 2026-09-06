import os
from functools import lru_cache

import torch
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

PRIMARY_MODEL_NAME = "meta-llama/Llama-Prompt-Guard-2-86M"
SECONDARY_MODEL_NAME = "protectai/deberta-v3-base-prompt-injection-v2"

# 인젝션 필터를 거치는 필드 목록
ADVERSARIAL_FIELDS = [
    "http.user_agent",
    "http.uri",
    "http.host",
    "dns.rrname",
    "tls.sni",
]

# 필드별로 secondary 모델 사용 여부를 다르게 설정한다
FIELD_USE_SECONDARY: dict[str, bool] = {
    "http.user_agent": False,
}


class InjectionFilterResult(BaseModel):
    is_injection: bool
    score: float  # max(primary, secondary)
    primary_score: float
    secondary_score: float


@lru_cache(maxsize=1)
def _load_primary():
    # gated 모델이라 HF_TOKEN이 필요하다
    token = os.environ.get("HF_TOKEN") or None
    tokenizer = AutoTokenizer.from_pretrained(PRIMARY_MODEL_NAME, token=token)
    model = AutoModelForSequenceClassification.from_pretrained(PRIMARY_MODEL_NAME, token=token)
    model.eval()
    return tokenizer, model


@lru_cache(maxsize=1)
def _load_secondary():
    # gated 아님 — 토큰 없이 로드된다.
    tokenizer = AutoTokenizer.from_pretrained(SECONDARY_MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(SECONDARY_MODEL_NAME)
    model.eval()
    return tokenizer, model


def _score(text: str, tokenizer, model, injection_label_index: int) -> float:
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        logits = model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[0]
    return probs[injection_label_index].item()


def check_injection(text: str, threshold: float = 0.5, use_secondary: bool = True) -> InjectionFilterResult:
    if not text:
        return InjectionFilterResult(is_injection=False, score=0.0, primary_score=0.0, secondary_score=0.0)

    primary_tok, primary_model = _load_primary()
    primary_score = _score(text, primary_tok, primary_model, injection_label_index=1)

    secondary_score = 0.0
    if use_secondary:
        secondary_tok, secondary_model = _load_secondary()
        secondary_score = _score(text, secondary_tok, secondary_model, injection_label_index=1)

    combined = max(primary_score, secondary_score)

    return InjectionFilterResult(
        is_injection=combined >= threshold,
        score=combined,
        primary_score=primary_score,
        secondary_score=secondary_score,
    )


def filter_flow_fields(flow: dict, threshold: float = 0.5) -> dict:
    """ADVERSARIAL_FIELDS 값을 검사해 인젝션으로 판정되면 빈 문자열로 치환한다."""
    result = dict(flow)
    for field in ADVERSARIAL_FIELDS:
        value = result.get(field)
        if isinstance(value, str):
            use_secondary = FIELD_USE_SECONDARY.get(field, True)
            if check_injection(value, threshold, use_secondary).is_injection:
                result[field] = ""
    return result
