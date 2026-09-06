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
    """확정이 아니라 후보 제시용 — 최종 확정은 check_rule_logic이 규칙 기반으로 한다."""
    scores: list[tuple[str, int]] = []
    for name, group in role_groups.items():
        result = check_rule_logic(rule_text, name, role_groups)
        score = sum(
            [
                _protocol_matches(rule_text, group),
                _classtype_matches(rule_text, group),
                _has_expected_keyword(rule_text, group),
            ]
        )
        if result.ok or score > 0:
            scores.append((name, score))

    scores.sort(key=lambda item: item[1], reverse=True)
    return [name for name, _ in scores]


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


def _has_expected_keyword(rule_text: str, group: RoleGroupDef) -> bool:
    return any(keyword in rule_text for keyword in group.expected_keywords)


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
    return "EXTERNAL_NET" in match.group("src") and "HOME_NET" in match.group("dst")
