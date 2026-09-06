from typing import Literal

from elasticsearch import AsyncElasticsearch

IndexName = Literal[
    "suricata-alert",
    "suricata-flow",
    "suricata-http",
    "suricata-dns",
    "suricata-tls",
    "nginx-access",
]

_INDEX_PATTERN = {name: f"{name}-*" for name in IndexName.__args__}

# 인덱스별로 반환할 필드를 화이트리스트로 제한한다
_RETURN_FIELDS: dict[str, list[str]] = {
    "suricata-alert": [
        "@timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "proto",
        "alert.signature_id", "alert.signature", "alert.category", "alert.severity",
    ],
    "suricata-flow": [
        "@timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "proto",
        "flow.pkts_toserver", "flow.pkts_toclient", "flow.bytes_toserver",
        "flow.bytes_toclient", "flow.age", "flow.state",
    ],
    "suricata-http": [
        "@timestamp", "src_ip", "dest_ip", "http.hostname", "http.url",
        "http.http_method", "http.http_user_agent", "http.status",
        "http.http_content_type", "http.length",
    ],
    "suricata-dns": [
        "@timestamp", "src_ip", "dest_ip", "dns.rrname", "dns.rrtype",
        "dns.rcode", "dns.answers_count",
    ],
    "suricata-tls": [
        "@timestamp", "src_ip", "dest_ip", "tls.sni", "tls.version", "tls.ja3.hash",
    ],
    "nginx-access": [
        "@timestamp", "src_ip", "nginx.path", "nginx.status", "nginx.request_time",
    ],
}

_MAX_LIMIT = 1000


async def es_query_events(
    client: AsyncElasticsearch,
    index: IndexName,
    start: str,
    end: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    signature_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    must: list[dict] = [{"range": {"@timestamp": {"gte": start, "lte": end}}}]
    if src_ip is not None:
        must.append({"term": {"src_ip": src_ip}})
    if dst_ip is not None:
        must.append({"term": {"dest_ip": dst_ip}})
    if dst_port is not None:
        must.append({"term": {"dest_port": dst_port}})
    if signature_id is not None:
        must.append({"term": {"alert.signature_id": signature_id}})

    response = await client.search(
        index=_INDEX_PATTERN[index],
        query={"bool": {"must": must}},
        size=min(limit, _MAX_LIMIT),
        source=_RETURN_FIELDS[index],
    )

    return [{"_id": hit["_id"], **hit["_source"]} for hit in response["hits"]["hits"]]
