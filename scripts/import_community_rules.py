"""ET Open 같은 커뮤니티 룰셋(suricata-update로 받은 것)을 RuleMemory에
origin="imported"로 가져온다.

가져온 룰은 alert 액션만, role_groups.yaml 기준으로 분류되는 것만
(scanning/web-attack) 임포트한다. LLM 프롬프트에는 안 들어가고
결정적 매칭 검사에는 전부 참여한다.
"""

import argparse
import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path

from meerkat.storage.rule_memory import RuleItem, RuleMemory
from meerkat.validation.logic_check import load_role_groups

_SID_RE = re.compile(r"\bsid:\s*(\d+)\s*;")
_CLASSTYPE_RE = re.compile(r"classtype:\s*([\w-]+)")


def classify_strict(rule_text: str, role_groups: dict) -> str | None:
    """classtype이 그룹의 classtypes 목록에 정확히 있을 때만 인정하는 엄격한 분류.
    propose_role_groups의 느슨한 폴백과 달리 프로토콜 디코더 이벤트 등이
    잘못 분류되는 것을 막는다."""
    match = _CLASSTYPE_RE.search(rule_text)
    if not match:
        return None
    classtype = match.group(1)
    for name, group in role_groups.items():
        if classtype in group.classtypes:
            return name
    return None


def parse_rules_file(path: Path) -> list[str]:
    rules = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(line)
    return rules


def is_alert_action(rule_text: str) -> bool:
    tokens = rule_text.split()
    return bool(tokens) and tokens[0] == "alert"


def extract_sid(rule_text: str) -> int | None:
    match = _SID_RE.search(rule_text)
    return int(match.group(1)) if match else None


async def import_rules(
    rules_path: str,
    local_sid_range: tuple[int, int] = (1000000, 1999999),
    limit: int | None = None,
) -> dict[str, int]:
    role_groups = load_role_groups()
    rule_memory = RuleMemory()

    existing = await rule_memory.list()
    known_sids = {r.sid for r in existing}

    stats = {"total_lines": 0, "not_alert": 0, "no_sid": 0, "sid_conflict": 0, "unclassified": 0, "imported": 0}
    now = datetime.now(timezone.utc)
    to_import: list[RuleItem] = []

    for rule_text in parse_rules_file(Path(rules_path)):
        stats["total_lines"] += 1

        if not is_alert_action(rule_text):
            stats["not_alert"] += 1
            continue

        sid = extract_sid(rule_text)
        if sid is None:
            stats["no_sid"] += 1
            continue

        if local_sid_range[0] <= sid <= local_sid_range[1] or sid in known_sids:
            stats["sid_conflict"] += 1
            continue

        role_group = classify_strict(rule_text, role_groups)
        if role_group is None:
            stats["unclassified"] += 1
            continue  # 우리 스코프(scanning/web-attack) 밖 — 안 가져온다

        to_import.append(
            RuleItem(
                sid=sid, rev=1, rule_text=rule_text, role_group=role_group,
                repr_event_ids=[], repr_pcap_path=None,
                created_at=now, updated_at=now, origin="imported",
            )
        )
        known_sids.add(sid)
        stats["imported"] += 1

        if limit is not None and stats["imported"] >= limit:
            break

    await rule_memory.bulk_upsert(to_import)
    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ET Open 등 커뮤니티 룰셋을 RuleMemory로 가져온다")
    parser.add_argument("rules_path", help="suricata-update가 받은 .rules 파일 경로")
    parser.add_argument("--limit", type=int, default=None, help="최대 가져올 개수 (테스트용)")
    args = parser.parse_args()

    result = asyncio.run(import_rules(args.rules_path, limit=args.limit))
    print(result)
