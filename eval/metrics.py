import re

from meerkat.validation.syntax import check_rule_syntax

RULE_FIELDS = ("protocol", "direction", "dst_port", "flow", "content", "action")


def syntax_accuracy(rule_texts: list[str], suricata_binary: str = "suricata") -> float:
    """SA: 수동 수정 없이 엔진이 로드하는 룰 비율."""
    if not rule_texts:
        return 0.0
    passing = sum(1 for rt in rule_texts if check_rule_syntax(rt, suricata_binary).ok)
    return passing / len(rule_texts)


def semantic_similarity(rule_text: str, reference_rule_text: str) -> float:
    """SS: 핵심 필드를 참조 룰과 비교해 일치 비율을 계산한다."""
    a = _extract_fields(rule_text)
    b = _extract_fields(reference_rule_text)
    total = sum(1 for field in RULE_FIELDS if b[field] is not None)
    if total == 0:
        return 0.0
    matches = sum(1 for field in RULE_FIELDS if a[field] == b[field] and a[field] is not None)
    return matches / total


def security_effectiveness(detection_rate: float, false_positive_rate: float) -> float:
    """SE = 0.5*DR + 0.5*(1-FPR)."""
    return 0.5 * detection_rate + 0.5 * (1 - false_positive_rate)


def alert_duplication_rate(alerts: list[dict]) -> float:
    """ADR: 중복 알럿 비율. alerts는 {"is_duplicate": bool, ...} 형태를 기대한다."""
    if not alerts:
        return 0.0
    duplicates = sum(1 for a in alerts if a.get("is_duplicate"))
    return duplicates / len(alerts)


def rule_count(rule_texts: list[str]) -> int:
    """RC: 생성된 룰 개수 — 적을수록 좋다."""
    return len(rule_texts)


def rule_usability_rate(rule_texts: list[str], suricata_binary: str = "suricata") -> float:
    """RUR: 포맷 검사 통과 + sid 중복 없음 → 실제 배포 가능한 비율."""
    if not rule_texts:
        return 0.0

    seen_sids: set[str] = set()
    usable = 0
    for rule_text in rule_texts:
        if not check_rule_syntax(rule_text, suricata_binary).ok:
            continue
        sid_match = re.search(r"sid:\s*(\d+)\s*;", rule_text)
        sid = sid_match.group(1) if sid_match else None
        if sid is not None and sid in seen_sids:
            continue
        if sid is not None:
            seen_sids.add(sid)
        usable += 1

    return usable / len(rule_texts)


def detection_latency(trigger_timestamps: list[tuple[float, float]]) -> float | None:
    """DL: (공격 시작 시각, 첫 알럿 시각) 쌍들의 평균 탐지 지연(초)."""
    if not trigger_timestamps:
        return None
    deltas = [alert_ts - start_ts for start_ts, alert_ts in trigger_timestamps]
    return sum(deltas) / len(deltas)


def _extract_fields(rule_text: str) -> dict[str, str | None]:
    header_tokens = rule_text.split("(")[0].split()
    action = header_tokens[0] if header_tokens else None
    protocol = header_tokens[1] if len(header_tokens) > 1 else None
    direction = "->" if "->" in rule_text else ("<>" if "<>" in rule_text else None)
    dst_port = header_tokens[-1] if header_tokens else None

    flow_match = re.search(r"flow:([^;]+);", rule_text)
    content_match = re.search(r'content:"([^"]*)"', rule_text)

    return {
        "protocol": protocol,
        "direction": direction,
        "dst_port": dst_port,
        "flow": flow_match.group(1).strip() if flow_match else None,
        "content": content_match.group(1) if content_match else None,
        "action": action,
    }
