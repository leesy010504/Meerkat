from datetime import datetime, timezone

from meerkat.storage.rule_memory import RuleItem, RuleMemory


async def record_generated_rule(
    rule_memory: RuleMemory,
    sid: int,
    rule_text: str,
    role_group: str,
    repr_event_ids: list[str],
    repr_pcap_path: str | None,
) -> RuleItem:
    now = datetime.now(timezone.utc)
    item = RuleItem(
        sid=sid,
        rev=1,
        rule_text=rule_text,
        role_group=role_group,
        repr_event_ids=repr_event_ids,
        repr_pcap_path=repr_pcap_path,
        created_at=now,
        updated_at=now,
        origin="generated",
    )
    await rule_memory.upsert(item)
    return item


async def record_repaired_rule(
    rule_memory: RuleMemory,
    sid: int,
    new_rule_text: str,
    new_event_ids: list[str],
) -> RuleItem:
    """기존 대표 샘플은 유지하고 새 샘플 id만 추가한다."""
    existing = await rule_memory.get(sid)
    merged_event_ids = list(dict.fromkeys(existing.repr_event_ids + new_event_ids))

    updated = existing.model_copy(
        update={
            "rev": existing.rev + 1,
            "rule_text": new_rule_text,
            "repr_event_ids": merged_event_ids,
            "origin": "repaired",
        }
    )
    await rule_memory.upsert(updated)
    return updated
