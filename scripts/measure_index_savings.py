"""스펙 §7 매핑 원칙의 절감 효과 측정 — 같은 로그를 두 가지 매핑으로 적재해 인덱스 크기를 비교한다.

  baseline : ES 동적 매핑 그대로 (모든 필드 색인, text+keyword 멀티필드, 기본 코덱)
  meerkat  : es_templates.py 매핑 (검색 필드만 명시 색인, 보관 전용 필드 index:false, best_compression)

스펙은 "ILM 삭제 정책만으로 계산한 수치는 근거가 약하다"고 했으므로, 동일 문서 집합을 실제로 넣고
force-merge 뒤 store 크기를 읽는다. 입력은 pcap(Suricata eve)이며 기본은 port_scan.pcap(flow 6.5만 건).

    uv run python scripts/measure_index_savings.py pcaps/attack/port_scan.pcap
"""

import argparse
import asyncio
import json

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from meerkat.config import load_settings
from meerkat.ingestion.es_templates import build_index_template
from meerkat.ingestion.eve_ingest import eve_to_document, run_suricata_to_eve

BASELINE_INDEX = "meerkat-measure-baseline"
MAPPING_ONLY_INDEX = "meerkat-measure-mapping-only"  # 문서는 원본 그대로, 매핑/코덱만 적용 → 매핑 효과 분리
MEERKAT_INDEX = "meerkat-measure-mapped"


async def _store_bytes(client: AsyncElasticsearch, index: str) -> int:
    await client.indices.forcemerge(index=index, max_num_segments=1)
    await client.indices.refresh(index=index)
    stats = await client.indices.stats(index=index, metric="store,docs")
    return stats["indices"][index]["primaries"]["store"]["size_in_bytes"]


async def measure(client: AsyncElasticsearch, pcap: str, suricata_binary: str) -> dict:
    events = run_suricata_to_eve(pcap, suricata_binary)
    # 비교 대상은 flow 문서 (가장 대량). raw 이벤트 전체(baseline)와 화이트리스트 문서(meerkat)를 각각 넣는다.
    raw_flows = [e for e in events if e.get("event_type") == "flow"]
    mapped = [doc for prefix, doc in map(lambda e: eve_to_document(e) or (None, None), events)
              if prefix == "suricata-flow"]
    for e in raw_flows:
        e["@timestamp"] = e.get("timestamp")

    indices = (BASELINE_INDEX, MAPPING_ONLY_INDEX, MEERKAT_INDEX)
    for index in indices:
        await client.indices.delete(index=index, ignore_unavailable=True)

    # baseline: 동적 매핑, 기본 코덱, 원본 문서 전체
    await client.indices.create(index=BASELINE_INDEX, settings={"number_of_shards": 1, "number_of_replicas": 0})
    await async_bulk(client, ({"_index": BASELINE_INDEX, "_source": e} for e in raw_flows))

    template = build_index_template("suricata-flow")["template"]
    settings = {k: v for k, v in template["settings"].items() if k != "index.lifecycle.name"}
    settings.update({"number_of_shards": 1, "number_of_replicas": 0})
    mappings = {**template["mappings"], "dynamic": False}

    # mapping-only: 원본 문서 전체를 넣되 매핑/코덱만 meerkat 식 → 색인 안 되는 필드는 _source에만 남는다
    await client.indices.create(index=MAPPING_ONLY_INDEX, settings=settings, mappings=mappings)
    await async_bulk(client, ({"_index": MAPPING_ONLY_INDEX, "_source": e} for e in raw_flows))

    # meerkat: 매핑/코덱 + 적재 단계 필드 화이트리스트(eve_to_document) — 실제 파이프라인 모양
    await client.indices.create(index=MEERKAT_INDEX, settings=settings, mappings=mappings)
    await async_bulk(client, ({"_index": MEERKAT_INDEX, "_source": d} for d in mapped))

    baseline_bytes = await _store_bytes(client, BASELINE_INDEX)
    mapping_only_bytes = await _store_bytes(client, MAPPING_ONLY_INDEX)
    mapped_bytes = await _store_bytes(client, MEERKAT_INDEX)
    for index in indices:
        await client.indices.delete(index=index, ignore_unavailable=True)

    def pct(b: int) -> float | None:
        return round((1 - b / baseline_bytes) * 100, 1) if baseline_bytes else None

    return {
        "pcap": pcap,
        "flow_docs": len(raw_flows),
        "baseline_dynamic_mapping_bytes": baseline_bytes,
        "mapping_only_bytes": mapping_only_bytes,
        "mapping_only_reduction_pct": pct(mapping_only_bytes),
        "meerkat_mapping_plus_whitelist_bytes": mapped_bytes,
        "meerkat_reduction_pct": pct(mapped_bytes),
        "note": "동일 문서 집합·force-merge 1세그먼트 기준 store 크기. mapping_only는 매핑/코덱 효과만, "
                "meerkat은 적재 시 필드 화이트리스트까지 포함. 보존 기간(ILM) 효과는 포함하지 않음.",
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcap", nargs="?", default="pcaps/attack/port_scan.pcap")
    parser.add_argument("--es", default=None)
    args = parser.parse_args()
    settings = load_settings()
    client = AsyncElasticsearch(hosts=[args.es] if args.es else settings.elasticsearch.hosts)
    try:
        result = await measure(client, args.pcap, settings.suricata.binary)
    finally:
        await client.close()
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
