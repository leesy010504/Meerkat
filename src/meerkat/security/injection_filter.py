import os
import re
from functools import lru_cache
from urllib.parse import unquote_plus

import torch
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from meerkat.security.lexical_prefilter import lexical_check

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

# 실제 로그 소스(eve.json / nginx access log)의 필드명 → 위 정규 필드명.
# 스케줄러가 LLM에 넘기는 flow_summary.sample_events는 ES 문서 그대로라서
# {"http": {"url": ..., "http_user_agent": ...}} 처럼 중첩돼 있고 이름도 다르다.
# 이 매핑이 없으면 필터는 최상위 "http.uri" 키만 보고 실제 공격자 통제 필드는
# 그대로 LLM에 들어간다.
FIELD_ALIASES: dict[str, str] = {
    "http.hostname": "http.host",
    "http.url": "http.uri",
    "http.http_user_agent": "http.user_agent",
    "http.http_refer": "http.uri",  # Referer도 URI 성격의 공격자 통제 필드
    "nginx.path": "http.uri",
    "nginx.user_agent": "http.user_agent",
    "nginx.host": "http.host",
    "dns.query": "dns.rrname",
    "tls.server_name": "tls.sni",
}

_ADVERSARIAL_SET = set(ADVERSARIAL_FIELDS)


class InjectionFilterResult(BaseModel):
    is_injection: bool
    score: float  # max(primary, secondary, lexical)
    primary_score: float
    secondary_score: float
    lexical_rule: str | None = None  # 결정적 사전 필터가 잡았으면 어느 규칙인지


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


MIN_WORDS_FOR_MODEL = 3
_WORD_RE = re.compile(r"[A-Za-z\u00C0-\uFFFF]{2,}")


def _word_count(text: str) -> int:
    """URL 디코딩 후 구분자(/ - _ . + 등)를 공백으로 본 단어 수. 숫자·hex 덩어리는 단어로 치지 않는다."""
    decoded = unquote_plus(text)
    return sum(1 for w in _WORD_RE.findall(decoded) if not re.fullmatch(r"[0-9a-fA-F]+", w))


def check_injection(
    text: str, threshold: float = 0.5, use_secondary: bool = True, use_lexical: bool = True
) -> InjectionFilterResult:
    if not text:
        return InjectionFilterResult(is_injection=False, score=0.0, primary_score=0.0, secondary_score=0.0)

    # 1단계: 결정적 어휘 규칙. 잡히면 모델을 돌리지 않는다 (CPU 절약 + 모델이 못 잡는 S2/S3 보강).
    if use_lexical:
        lexical = lexical_check(text)
        if lexical.is_injection:
            return InjectionFilterResult(
                is_injection=True, score=1.0, primary_score=0.0, secondary_score=0.0,
                lexical_rule=lexical.rule,
            )

    # 2단계 전 가드: 자연어 문장이 안 되는 짧은 토큰(예: "/admin.bak", UUID 경로)은 분류 모델이
    # 근거 없이 높은 점수를 내는 일이 있다(디렉토리 탐색 pcap의 URL이 지워져 LLM 근거가 사라졌다).
    # 지시문은 최소 몇 단어가 필요하니, 구분자를 공백으로 펴서 단어가 MIN_WORDS 미만이면 모델을 건너뛴다.
    if _word_count(text) < MIN_WORDS_FOR_MODEL:
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


def canonical_field(path: str) -> str | None:
    """점 경로를 정규 필드명으로 바꾼다. 필터 대상이 아니면 None.

    경로 전체("http.url")와 마지막 두 세그먼트("sample_events.http.url" → "http.url")를
    모두 본다 — 래퍼 키 아래 중첩된 ES 문서도 같은 필드로 취급하기 위해서다.
    """
    segments = path.split(".")
    candidates = [path]
    if len(segments) > 2:
        candidates.append(".".join(segments[-2:]))
    for candidate in candidates:
        name = FIELD_ALIASES.get(candidate, candidate)
        if name in _ADVERSARIAL_SET:
            return name
    return None


def filter_flow_fields(flow: dict, threshold: float = 0.5) -> dict:
    """공격자 통제 필드 값을 검사해 인젝션으로 판정되면 빈 문자열로 치환한다.

    최상위 점 표기 키("http.uri")뿐 아니라 중첩 dict({"http": {"url": ...}})와
    리스트(sample_events) 안까지 재귀적으로 훑는다. 원본은 바꾸지 않는다.
    """
    filtered, _ = _filter_node(flow, "", threshold)
    return filtered


def filter_flow_fields_with_report(flow: dict, threshold: float = 0.5) -> tuple[dict, list[str]]:
    """filter_flow_fields와 같지만 치환된 필드의 경로 목록도 돌려준다 (로그/PR 본문용)."""
    return _filter_node(flow, "", threshold)


def _filter_node(node, prefix: str, threshold: float) -> tuple[object, list[str]]:
    blanked: list[str] = []

    if isinstance(node, dict):
        out: dict = {}
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            canonical = canonical_field(path)
            if canonical is not None and isinstance(value, str):
                use_secondary = FIELD_USE_SECONDARY.get(canonical, True)
                if check_injection(value, threshold, use_secondary).is_injection:
                    out[key] = ""
                    blanked.append(path)
                    continue
                out[key] = value
                continue
            out[key], sub = _filter_node(value, path, threshold)
            blanked.extend(sub)
        return out, blanked

    if isinstance(node, list):
        items = []
        for value in node:
            # 리스트 인덱스는 경로에 넣지 않는다 — sample_events[3].http.url도 http.url로 본다
            filtered, sub = _filter_node(value, prefix, threshold)
            items.append(filtered)
            blanked.extend(sub)
        return items, blanked

    return node, blanked
