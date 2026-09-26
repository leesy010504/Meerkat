"""rules/*.rules(GitOps 소스)에 있는데 rule_memory에 없는 룰을 origin="manual"로 등록한다.

왜 필요한가: 관계 판단(변종 vs 신규)과 기존 룰셋 선검사(AlreadyCovered)는 rule_memory만 본다.
사람이 rules/에 직접 넣은 룰이 메모리에 없으면 에이전트는 그 룰을 모른 채 비슷한 룰을 또 만든다.
sid 충돌은 reserved_sids로 막아두었지만, "이미 커버됨" 판단에는 메모리에 있어야 한다.

    uv run python scripts/sync_rules_to_memory.py            # rules/ → .meerkat/rule_memory.json
    uv run python scripts/sync_rules_to_memory.py --dry-run
"""

import argparse
import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path

from meerkat.storage.rule_memory import RuleItem, RuleMemory

_SID_RE = re.compile(r"\bsid:\s*(\d+)\s*;")
_REV_RE = re.compile(r"\brev:\s*(\d+)\s*;")


async def sync(rules_dir: str, memory_path: str, dry_run: bool = False) -> dict[str, int]:
    memory = RuleMemory(path=memory_path)
    existing = {item.sid: item for item in await memory.list()}
    now = datetime.now(timezone.utc)
    stats = {"seen": 0, "added": 0, "updated": 0, "unchanged": 0, "skipped_no_sid": 0}
    to_upsert: list[RuleItem] = []

    for path in sorted(Path(rules_dir).glob("*.rules")):
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            stats["seen"] += 1
            sid_match = _SID_RE.search(line)
            if not sid_match:
                stats["skipped_no_sid"] += 1
                continue
            sid = int(sid_match.group(1))
            rev_match = _REV_RE.search(line)
            rev = int(rev_match.group(1)) if rev_match else 1
            current = existing.get(sid)
            if current is None:
                to_upsert.append(RuleItem(
                    sid=sid, rev=rev, rule_text=line, role_group=path.stem, repr_event_ids=[],
                    repr_pcap_path=None, created_at=now, updated_at=now, origin="manual",
                ))
                stats["added"] += 1
            elif current.rule_text.strip() != line:
                # 파일이 진실의 원천 — 사람이 파일을 고쳤으면 메모리를 따라가게 한다 (origin은 유지)
                to_upsert.append(current.model_copy(update={"rule_text": line, "rev": rev, "role_group": path.stem}))
                stats["updated"] += 1
            else:
                stats["unchanged"] += 1

    if not dry_run and to_upsert:
        await memory.bulk_upsert(to_upsert)
    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules-dir", default="rules")
    parser.add_argument("--memory", default=".meerkat/rule_memory.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(asyncio.run(sync(args.rules_dir, args.memory, args.dry_run)))
