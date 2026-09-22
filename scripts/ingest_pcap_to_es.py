"""pcap을 Suricata로 돌려 eve 이벤트를 로컬 ES에 적재한다.

    uv run python scripts/ingest_pcap_to_es.py pcaps/attack/dir_bruteforce.pcap --shift-to-now
    uv run python scripts/ingest_pcap_to_es.py pcaps/benign/*.pcap --rules rules/scanning.rules

--shift-to-now: 캡처 시각을 "지금"으로 평행이동해서 스케줄러의 최근 윈도우에 들어가게 한다.
--rules:        룰셋을 함께 돌려 alert 이벤트도 적재한다 (없으면 flow/http/dns/tls만).
"""

import argparse
import asyncio

from elasticsearch import AsyncElasticsearch

from meerkat.config import load_settings
from meerkat.ingestion.es_templates import build_all_templates
from meerkat.ingestion.eve_ingest import (
    bulk_index_documents,
    eve_to_document,
    run_suricata_to_eve,
    shift_timestamps_to_now,
)


async def ensure_templates(client: AsyncElasticsearch) -> None:
    for name, template in build_all_templates().items():
        await client.indices.put_index_template(
            name=f"meerkat-{name}", index_patterns=template["index_patterns"], template=template["template"]
        )


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcaps", nargs="+")
    parser.add_argument("--rules", default=None, help="alert도 적재하려면 룰 파일 경로")
    parser.add_argument("--shift-to-now", action="store_true")
    parser.add_argument("--es", default=None, help="ES URL (기본: config/settings.yaml)")
    args = parser.parse_args()

    settings = load_settings()
    client = AsyncElasticsearch(hosts=[args.es] if args.es else settings.elasticsearch.hosts)
    try:
        await ensure_templates(client)
        for pcap in args.pcaps:
            events = run_suricata_to_eve(pcap, settings.suricata.binary, args.rules)
            docs = [d for d in map(eve_to_document, events) if d is not None]
            if args.shift_to_now:
                docs = shift_timestamps_to_now(docs)
            counts = await bulk_index_documents(client, docs)
            print(f"{pcap}: {len(events)} eve events -> {sum(counts.values())} docs {counts}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
