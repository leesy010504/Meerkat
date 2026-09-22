"""nginx access log(combined 포맷)를 nginx-access 인덱스에 적재한다.

    docker logs meerkat-target-nginx-1 2>/dev/null | uv run python scripts/ingest_nginx_access.py --shift-to-now
    uv run python scripts/ingest_nginx_access.py --file /var/log/nginx/access.log
"""

import argparse
import asyncio
import sys

from elasticsearch import AsyncElasticsearch
from ingest_pcap_to_es import ensure_templates

from meerkat.config import load_settings
from meerkat.ingestion.eve_ingest import (
    bulk_index_documents,
    nginx_lines_to_documents,
    shift_timestamps_to_now,
)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--file", default=None, help="로그 파일 경로 (없으면 stdin)")
    parser.add_argument("--shift-to-now", action="store_true")
    parser.add_argument("--es", default=None)
    args = parser.parse_args()

    if args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as f:
            docs = list(nginx_lines_to_documents(f))
    else:
        docs = list(nginx_lines_to_documents(sys.stdin))
    if args.shift_to_now:
        docs = shift_timestamps_to_now(docs)

    settings = load_settings()
    client = AsyncElasticsearch(hosts=[args.es] if args.es else settings.elasticsearch.hosts)
    try:
        await ensure_templates(client)
        counts = await bulk_index_documents(client, docs)
        print(f"{len(docs)} access log lines -> {counts}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
