from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel


class FailureItem(BaseModel):
    id: str
    created_at: datetime
    metric: str
    role_group_hint: str
    src_ip: str
    reason: str
    flow_summary: dict
    draft_rule_text: str | None = None
    proposed_category: str | None = None
    proposed_role_group: dict | None = None
    proposal_reasoning: str | None = None


class FailureQueue:
    """orchestrate()가 룰을 못 만들고 실패한 케이스를 기록한다.

    자동 알림은 없다 — 사람이 주기적으로 list()를 조회해 새 role_group이
    필요한지 판단하는 용도.
    """

    def __init__(self, path: str | Path = ".meerkat/failure_queue.json"):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("{}")

    async def add(
        self,
        *,
        metric: str,
        role_group_hint: str,
        src_ip: str,
        reason: str,
        flow_summary: dict,
        draft_rule_text: str | None = None,
        proposed_category: str | None = None,
        proposed_role_group: dict | None = None,
        proposal_reasoning: str | None = None,
    ) -> FailureItem:
        item = FailureItem(
            id=str(uuid4()),
            created_at=datetime.now(timezone.utc),
            metric=metric,
            role_group_hint=role_group_hint,
            src_ip=src_ip,
            reason=reason,
            flow_summary=flow_summary,
            draft_rule_text=draft_rule_text,
            proposed_category=proposed_category,
            proposed_role_group=proposed_role_group,
            proposal_reasoning=proposal_reasoning,
        )
        data = self._load()
        data[item.id] = json.loads(item.model_dump_json())
        self._save(data)
        return item

    async def list(self) -> list[FailureItem]:
        return [FailureItem.model_validate(v) for v in self._load().values()]

    def _load(self) -> dict[str, dict]:
        return json.loads(self._path.read_text())

    def _save(self, data: dict[str, dict]) -> None:
        self._path.write_text(json.dumps(data, indent=2))
