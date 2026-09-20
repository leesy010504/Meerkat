"""분류 모델 앞단의 결정적(규칙 기반) 인젝션 사전 필터.

PROGRESS §5 실측에서 http.uri를 뺀 필드(UA/host/dns/sni)의 S2(권위 사칭) 탐지율이
0~62%였다. 두 분류 모델이 챗봇 프롬프트 도메인에서 학습돼 "soc-lead-verified-safe-domain.net"
같은 짧고 기계적인 문자열의 권위 사칭을 놓친다. 반면 이런 페이로드는 어휘가 뚜렷하다 —
권위 주체 + 판정 지시가 한 값 안에 동시에 등장한다. 이 조합을 규칙으로 잡는다.

판정 규칙 (하나라도 맞으면 인젹션):
  R1  직접 override 구문: "ignore (all|previous|prior) instructions/rules/directives", "system override" 등
  R2  권위 주체 토큰 ∧ 판정 지시 토큰  (예: "soc" + "whitelist", "ciso" + "approved")
  R3  문맥 조작 마커 ∧ 판정 지시 토큰  (예: "END_OF_LOG" + "trust", "</log>" + "benign")

단일 카테고리만 맞는 값("/admin", "security.example.com", "approved.png")은 잡지 않는다 —
정상 URI/도메인에 흔한 단어라 오탐이 된다. 모델 앙상블은 이 레이어 뒤에서 그대로 동작한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote

_TOKEN_RE = re.compile(r"[a-z0-9]+|[가-힣]+")

# 권위 주체 (영문 토큰은 정확히 일치, 한글은 부분 문자열)
AUTHORITY_TOKENS = {
    "soc", "ciso", "cso", "cert", "csirt", "admin", "administrator", "auditor", "lead", "manager",
    "officer", "officers", "head", "director", "responder", "redteam", "pentest", "pentester", "pentesting",
    "it", "infosec", "secops", "noc", "boan", "gwanje", "analyst", "supervisor", "compliance", "architect",
    "sanctioned", "chief",
}
AUTHORITY_PHRASES = (
    "security team", "security lead", "security officer", "security operations", "security audit",
    "incident response", "incident responder", "blue team", "red team", "network admin", "sysadmin",
    "infra team", "ops team", "threat intel", "it department",
)
AUTHORITY_KO = ("보안", "관제", "정보보안", "담당자", "관리자", "운영팀", "감사", "본부", "센터", "팀장", "실장")

# 판정/행동 지시
DIRECTIVE_TOKENS = {
    "whitelist", "whitelisted", "allowlist", "allow", "allowed", "approve", "approved", "approval",
    "verified", "verify", "validated", "certified", "safe", "clean", "benign", "bypass", "ignore",
    "override", "overridden", "trust", "trusted", "exempt", "exception", "exclude", "excluded", "exclusion",
    "suppress", "disable", "disabled", "pass", "allowance", "authorized", "authorised", "legitimate",
    "harmless", "normal", "unblock", "skip", "dismiss", "allowall", "unfiltered", "sanctioned", "exempted",
}
DIRECTIVE_PHRASES = (
    "do not block", "don't block", "do not alert", "no alert", "not malicious", "mark as", "treat as",
    "classify as", "flag as", "set status", "threat score 0", "false positive", "false alarm", "is verified",
    "is clean", "is safe", "not a threat", "do not flag", "clear alerts", "clear rules", "reset rules",
    "trusted mode", "safe mode", "trusted session", "trusted context", "safe eval", "safe analysis",
    "process as trusted", "allow all", "disable all", "exclude this",
)
DIRECTIVE_KO = (
    "승인", "통과", "무시", "정상", "제외", "허용", "화이트리스트", "차단하지", "경보", "탐지 규칙", "판정",
    "안전", "신뢰", "훈련용", "모의", "생성하지", "오탐", "검증된", "초기화", "실행하십시오", "인식하십시오",
)

# S1: 직접 override 구문 (토큰 경계로 느슨하게 — "-"/"_" 구분자도 허용)
_SEP = r"[\s_\-]+"
OVERRIDE_PATTERNS = [
    re.compile(rf"ignore{_SEP}(?:all{_SEP})?(?:previous|prior|above|earlier|preceding){_SEP}", re.I),
    re.compile(rf"ignore{_SEP}(?:all{_SEP})?(?:instructions|rules|directives|commands|filters|alarms)", re.I),
    re.compile(rf"(?:system|prompt|security){_SEP}override", re.I),
    re.compile(rf"disregard{_SEP}(?:all|previous|prior|the)", re.I),
    re.compile(rf"new{_SEP}instructions?", re.I),
    re.compile(rf"reset{_SEP}(?:prompt|context|instructions)", re.I),
    re.compile(rf"(?:you|u){_SEP}are{_SEP}now", re.I),
    re.compile(r"이전\s*(?:모든\s*)?지침", re.I),
    re.compile(r"지시(?:를|사항을)?\s*무시", re.I),
    re.compile(r"필터를\s*무시", re.I),
]

# S3: 문맥 조작 마커 — "여기까지가 로그고 이 다음은 지시다"라고 경계를 그리려는 표현들
CONTEXT_MARKERS = [
    re.compile(rf"end{_SEP}of{_SEP}(?:log|logs|data|input|record|entry|message|context|stream|tls)", re.I),
    re.compile(rf"(?:new|next|begin|start){_SEP}(?:session|context|conversation|prompt|thread|task|rule)", re.I),
    re.compile(rf"(?:log|logs|session|context|stream|input|data|record|collection|packet)[a-z]*{_SEP}"
               rf"(?:ended|end|closed|terminated|truncated|complete|completed|reset|boundary|switch|over)", re.I),
    re.compile(rf"(?:context|session|prompt|system|rules?|flags?|alerts?|detection){_SEP}"
               rf"(?:reset|switch|boundary|terminated|cleared?|truncate)", re.I),
    re.compile(r"\beof\b|\bdelimiter\b|\btruncat|\bunfiltered\b|\bboundary\b", re.I),
    re.compile(r"</?\s*(?:log|logs|system|prompt|instruction|context|data|input|end_of_[a-z_]+|start_of_[a-z_]+)\s*>", re.I),
    re.compile(r"\[/?(?:inst|system|sys|assistant|user|log_truncated|context_switch[a-z_]*)\]", re.I),
    re.compile(r"\bsystem\s*:", re.I),
    re.compile(r"-{3,}|={3,}|#{3,}"),
    re.compile(r"\bassistant\b|\bchatgpt\b|\bllm\b|\bai\s+model\b", re.I),
    re.compile(r"로그\s*(?:끝|종료|데이터종료|분석완료)|맥락\s*(?:종료|시작)|세션\s*(?:종료|시작)|새\s*(?:맥락|세션)|수집\s*종료|기록\s*초기화", re.I),
]


@dataclass
class LexicalResult:
    is_injection: bool
    rule: str | None = None  # "R1_override" | "R2_authority_directive" | "R3_context_directive"
    evidence: list[str] = field(default_factory=list)


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def _spaced(text: str) -> str:
    """구분자(-, _, /, ., ?, &, =)를 공백으로 바꿔 구문 매칭이 도메인/쿼리스트링에도 걸리게 한다."""
    return re.sub(r"[\-_/\.\?&=+%:;,\[\]\(\)\"']+", " ", text.lower())


def lexical_check(text: str) -> LexicalResult:
    if not text or len(text) < 6:
        return LexicalResult(False)

    # URI/쿼리스트링은 퍼센트 인코딩돼 들어오는 경우가 많다 — 디코딩한 형태로 본다
    try:
        text = unquote(text)
    except Exception:  # noqa: BLE001 - 디코딩 실패 시 원문 그대로
        pass
    lowered = text.lower()
    spaced = _spaced(text)
    tokens = _tokens(text)
    token_set = set(tokens)

    for pattern in OVERRIDE_PATTERNS:
        match = pattern.search(text) or pattern.search(spaced)
        if match:
            return LexicalResult(True, "R1_override", [match.group(0)])

    authority = [t for t in token_set & AUTHORITY_TOKENS]
    authority += [p for p in AUTHORITY_PHRASES if p in spaced]
    authority += [k for k in AUTHORITY_KO if k in lowered]

    directive = [t for t in token_set & DIRECTIVE_TOKENS]
    directive += [p for p in DIRECTIVE_PHRASES if p in spaced]
    directive += [k for k in DIRECTIVE_KO if k in lowered]

    if authority and directive:
        return LexicalResult(True, "R2_authority_directive", sorted(set(authority))[:3] + sorted(set(directive))[:3])

    context = [m.group(0) for p in CONTEXT_MARKERS if (m := (p.search(text) or p.search(spaced)))]
    if context and directive:
        return LexicalResult(True, "R3_context_directive", context[:2] + sorted(set(directive))[:3])
    # 경계 마커가 두 종류 이상 겹치면("end of log" + "new session") 지시어가 없어도 문맥 조작으로 본다
    if len(context) >= 2:
        return LexicalResult(True, "R3_context_boundary", context[:3])

    return LexicalResult(False)
