"""배포된 룰(sid)별 알럿량 리포트 — 사후 모니터링(Phase 3 ⑪)의 읽기 전용 버전.

ES suricata-alert 인덱스에서 최근 N시간 동안 sid별 알럿 수와 고유 src_ip 수를 집계해,
전체 알럿의 일정 비율 이상을 혼자 차지하는 sid를 "noisy"로 표시한다. 자동 비활성화는
하지 않는다(에이전트는 룰을 끄지 않는다는 원칙) — 사람이 보고 revert PR을 판단한다.

    uv run python scripts/rule_alert_report.py --hours 24 --noisy-share 0.5
"""

import argparse
import asyncio
import datetime
import json

from elasticsearch import AsyncElasticsearch

from meerkat.config import load_settings
from meerkat.storage.rule_memory import RuleMemory


async def collect(client: AsyncElasticsearch, hours: int, noisy_share: float) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(hours=hours)
    response = await client.search(
        index="suricata-alert-*",
        size=0,
        query={"range": {"@timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
        aggs={
            "by_sid": {
                "terms": {"field": "alert.signature_id", "size": 200, "order": {"_count": "desc"}},
                "aggs": {"unique_src": {"cardinality": {"field": "src_ip"}}},
            }
        },
    )
    buckets = response.get("aggregations", {}).get("by_sid", {}).get("buckets", [])
    total = sum(b["doc_count"] for b in buckets)

    memory = RuleMemory()
    known = {item.sid: item for item in await memory.list()}

    rows = []
    for bucket in buckets:
        sid = int(bucket["key"])
        item = known.get(sid)
        share = bucket["doc_count"] / total if total else 0.0
        rows.append({
            "sid": sid,
            "alerts": bucket["doc_count"],
            "unique_src_ips": bucket["unique_src"]["value"],
            "share": round(share, 3),
            "noisy": share >= noisy_share and len(buckets) > 1,
            "role_group": item.role_group if item else None,
            "origin": item.origin if item else "unknown",
            "rev": item.rev if item else None,
        })
    return {"window_hours": hours, "total_alerts": total, "rules": rows,
            "generated_at": now.isoformat()}


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--noisy-share", type=float, default=0.5,
                        help="전체 알럿 중 이 비율 이상을 한 sid가 내면 noisy로 표시")
    parser.add_argument("--es", default=None)
    args = parser.parse_args()

    settings = load_settings()
    client = AsyncElasticsearch(hosts=[args.es] if args.es else settings.elasticsearch.hosts)
    try:
        report = await collect(client, args.hours, args.noisy_share)
    finally:
        await client.close()
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
