from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel


class RuleItem(BaseModel):
    sid: int
    rev: int
    rule_text: str
    role_group: str
    repr_event_ids: list[str]
    repr_pcap_path: str | None = None
    created_at: datetime
    updated_at: datetime
    origin: Literal["generated", "repaired", "imported"]


class RuleMemory:
    """룰 저장소. 대표 샘플(repr_event_ids/repr_pcap_path)을 함께 관리한다."""

    def __init__(self, path: str | Path = ".meerkat/rule_memory.json"):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("{}")

    async def list(self) -> list[RuleItem]:
        return [RuleItem.model_validate(v) for v in self._load().values()]

    async def get(self, sid: int) -> RuleItem:
        data = self._load()
        key = str(sid)
        if key not in data:
            raise KeyError(f"no rule with sid {sid}")
        return RuleItem.model_validate(data[key])

    async def upsert(self, item: RuleItem) -> None:
        data = self._load()
        item = item.model_copy(update={"updated_at": datetime.now(timezone.utc)})
        data[str(item.sid)] = json.loads(item.model_dump_json())
        self._save(data)

    async def bulk_upsert(self, items: list[RuleItem]) -> None:
        """여러 건을 한 번에 upsert한다. 파일을 한 번만 읽고 쓴다."""
        if not items:
            return
        data = self._load()
        now = datetime.now(timezone.utc)
        for item in items:
            item = item.model_copy(update={"updated_at": now})
            data[str(item.sid)] = json.loads(item.model_dump_json())
        self._save(data)

    async def existing_sids(self) -> set[int]:
        return {int(k) for k in self._load()}

    def _load(self) -> dict[str, dict]:
        return json.loads(self._path.read_text())

    def _save(self, data: dict[str, dict]) -> None:
        self._path.write_text(json.dumps(data, indent=2))
