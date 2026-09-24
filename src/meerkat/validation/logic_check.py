import re
from pathlib import Path

import yaml
from pydantic import BaseModel


class RoleGroupDef(BaseModel):
    protocols: list[str]
    direction: str
    expected_keywords: list[str] = []
    classtypes: list[str] = []
    target_services: list[str] = []


class LogicCheckResult(BaseModel):
    ok: bool
    group: str
    reasons: list[str]


def load_role_groups(path: str | Path = "config/role_groups.yaml") -> dict[str, RoleGroupDef]:
    raw = yaml.safe_load(Path(path).read_text())
    return {name: RoleGroupDef.model_validate(v) for name, v in raw["groups"].items()}


def propose_role_groups(rule_text: str, role_groups: dict[str, RoleGroupDef]) -> list[str]:
    """확정이 아니라 후보 제시용 — 최종 확정은 check_rule_logic이 규칙 기반으로 한다.

    protocol, classtype(정의돼 있으면), expected_keywords(정의돼 있으면), 방향 전부 \
    일치해야 후보 자격이 있다 — check_rule_logic의 필수조건과 동일하게 맞춘다. \
    이 중 하나라도 가점 취급하면, 예를 들어 threshold/detection_filter처럼 여러 \
    그룹에 공통으로 등장하는 키워드 하나만으로 protocol/classtype이 안 맞는 \
    그룹에 잘못 배정될 수 있다. 방향도 마찬가지다 — 여기서 방향을 빼면 LLM 후보가 \
    방향 불일치로 거부된 룰이 폴백 경로로 같은 그룹에 그대로 배정돼 검사가 무의미해진다.
    """
    candidates: list[str] = []
    for name, group in role_groups.items():
        if not _protocol_matches(rule_text, group):
            continue
        if group.classtypes and not _classtype_matches(rule_text, group):
            continue
        if group.expected_keywords and not _has_expected_keyword(rule_text, group):
            continue
        if not _direction_matches(rule_text, group):
            continue
        candidates.append(name)

    return candidates


def check_rule_logic(
    rule_text: str, claimed_group: str, role_groups: dict[str, RoleGroupDef]
) -> LogicCheckResult:
    group = role_groups.get(claimed_group)
    if group is None:
        return LogicCheckResult(ok=False, group=claimed_group, reasons=[f"unknown role group: {claimed_group}"])

    reasons: list[str] = []

    if not _protocol_matches(rule_text, group):
        reasons.append(f"protocol not in {group.protocols}")

    if group.classtypes and not _classtype_matches(rule_text, group):
        reasons.append(f"classtype not in {group.classtypes}")

    if group.expected_keywords and not _has_expected_keyword(rule_text, group):
        reasons.append(f"none of expected keywords present: {group.expected_keywords}")

    if not _direction_matches(rule_text, group):
        reasons.append(f"direction does not match expected '{group.direction}'")

    return LogicCheckResult(ok=len(reasons) == 0, group=claimed_group, reasons=reasons)


def _extract_protocol(rule_text: str) -> str | None:
    parts = rule_text.strip().split()
    return parts[1].lower() if len(parts) > 1 else None


def _extract_classtype(rule_text: str) -> str | None:
    match = re.search(r"classtype:\s*([\w-]+)", rule_text)
    return match.group(1) if match else None


def _protocol_matches(rule_text: str, group: RoleGroupDef) -> bool:
    proto = _extract_protocol(rule_text)
    if proto is None:
        return False
    if proto in group.protocols:
        return True
    # http/tls/dns 등 app-layer 프로토콜은 헤더에 tcp/udp로 적히는 경우가 많으니
    # 룰 본문에 프로토콜 이름이 버퍼로 등장하는지도 함께 본다.
    return any(p in rule_text.lower() for p in group.protocols if p not in ("tcp", "udp", "icmp"))


def _classtype_matches(rule_text: str, group: RoleGroupDef) -> bool:
    classtype = _extract_classtype(rule_text)
    return classtype is not None and classtype in group.classtypes


_FULL_HEADER_RE = re.compile(
    r"^\S+\s+\S+\s+\S+\s+\S+\s+(?:->|<>)\s+\S+\s+(?P<dst_port>\S+)\s*$"
)


def _extract_dest_port(rule_text: str) -> str | None:
    header = rule_text.split("(")[0].strip()
    match = _FULL_HEADER_RE.match(header)
    return match.group("dst_port") if match else None


def _has_expected_keyword(rule_text: str, group: RoleGroupDef) -> bool:
    dest_port = _extract_dest_port(rule_text)
    for keyword in group.expected_keywords:
        if keyword.isdigit():
            # 포트 번호는 헤더의 목적지 포트 필드와 정확히 일치할 때만 인정한다 —
            # 룰 전체에서 부분 문자열로 찾으면 sid나 CVE 번호 등과 우연히 겹칠 수 있다
            # (예: sid가 253이면 "53"이 문자열로는 포함돼 있음).
            if dest_port == keyword:
                return True
        elif keyword in rule_text:
            return True
    return False


_HEADER_RE = re.compile(
    r"^\S+\s+\S+\s+(?P<src>\S+)\s+\S+\s+(?:->|<>)\s+(?P<dst>\S+)\s+\S+\s*$"
)


def _direction_matches(rule_text: str, group: RoleGroupDef) -> bool:
    if group.direction != "inbound":
        return True

    header = rule_text.split("(")[0].strip()
    match = _HEADER_RE.match(header)
    if match is None:
        return False

    # inbound는 EXTERNAL_NET이 출발지, HOME_NET이 목적지여야 한다
    if "EXTERNAL_NET" in match.group("src") and "HOME_NET" in match.group("dst"):
        return True
    # 응답 쪽을 보는 룰(flow:to_client — 예: 외부 출발지로 나가는 404 폭증)은 헤더가 뒤집혀 있어도
    # 공격 자체는 inbound다. 헤더가 HOME_NET → EXTERNAL_NET이고 to_client/from_server일 때만 인정한다.
    responder_side = re.search(r"flow\s*:[^;]*\b(to_client|from_server)\b", rule_text) is not None
    return responder_side and "HOME_NET" in match.group("src") and "EXTERNAL_NET" in match.group("dst")
