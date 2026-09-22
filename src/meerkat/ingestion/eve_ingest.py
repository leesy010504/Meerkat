"""Suricata eve.json / nginx access log → Elasticsearch 적재.

운영 환경에서는 Filebeat가 이 일을 하지만(deploy/k8s/21-filebeat-configmap.yaml),
로컬에서 파이프라인 전체(pcap → Suricata → ES → 스케줄러 → 오케스트레이터)를
돌려보려면 같은 모양의 문서를 직접 넣어줄 수단이 필요하다. 문서 모양은
es_templates.py의 매핑과 es_query.py의 반환 필드 화이트리스트에 맞춘다.
"""

from __future__ import annotations

import datetime
import json
import re
import subprocess
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

# eve.json event_type → 적재할 인덱스 접두사. 여기 없는 타입(stats, fileinfo 등)은 버린다.
EVE_INDEX_PREFIX: dict[str, str] = {
    "alert": "suricata-alert",
    "flow": "suricata-flow",
    "http": "suricata-http",
    "dns": "suricata-dns",
    "tls": "suricata-tls",
}

# 인덱스별로 보존할 중첩 필드 — 템플릿 매핑과 동일하게 유지한다 (원본 페이로드 등은 안 넣는다)
_NESTED_KEEP: dict[str, dict[str, tuple[str, ...]]] = {
    "suricata-alert": {"alert": ("signature_id", "signature", "category", "severity")},
    "suricata-flow": {
        "flow": ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "age", "state")
    },
    "suricata-http": {
        "http": ("hostname", "url", "http_method", "http_user_agent", "status", "http_content_type", "length")
    },
    "suricata-dns": {"dns": ("rrname", "rrtype", "rcode", "answers_count")},
    "suricata-tls": {"tls": ("sni", "version", "ja3")},
}

_COMMON_KEYS = ("src_ip", "dest_ip", "src_port", "dest_port", "proto", "event_type", "flow_id")

_IPV6_LOOPBACK_LONG = "0000:0000:0000:0000:0000:0000:0000:0001"


def run_suricata_to_eve(pcap_path: str | Path, suricata_binary: str = "suricata",
                        rules_path: str | Path | None = None) -> list[dict]:
    """pcap을 Suricata로 돌려 eve.json 이벤트 목록을 돌려준다.

    rules_path가 None이면 룰 없이(-S /dev/null) 돌린다 — flow/http/dns/tls 같은
    프로토콜 이벤트만 얻고 alert는 생기지 않는다. 룰셋을 주면 alert도 함께 나온다.
    """
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [
            suricata_binary, "-r", str(pcap_path), "-l", tmp, "-k", "none", "--runmode", "single",
            "-S", str(rules_path) if rules_path else "/dev/null",
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        eve = Path(tmp) / "eve.json"
        if not eve.exists():
            return []
        events = []
        for line in eve.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events


def normalize_ip(value: str | None) -> str | None:
    """Suricata는 IPv6를 풀어쓴 형태로 낸다 — ES `ip` 타입은 둘 다 받지만 보기 좋게 압축한다."""
    if value is None:
        return None
    if value == _IPV6_LOOPBACK_LONG:
        return "::1"
    if ":" in value:
        import ipaddress

        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value
    return value


def eve_to_document(event: dict) -> tuple[str, dict] | None:
    """eve 이벤트 하나를 (인덱스 접두사, ES 문서)로 바꾼다. 적재 대상이 아니면 None."""
    prefix = EVE_INDEX_PREFIX.get(event.get("event_type", ""))
    if prefix is None:
        return None

    doc: dict = {"@timestamp": event.get("timestamp")}
    for key in _COMMON_KEYS:
        if key in event:
            doc[key] = event[key]
    doc["src_ip"] = normalize_ip(doc.get("src_ip"))
    doc["dest_ip"] = normalize_ip(doc.get("dest_ip"))

    for nested_key, fields in _NESTED_KEEP.get(prefix, {}).items():
        nested = event.get(nested_key)
        if isinstance(nested, dict):
            doc[nested_key] = {f: nested[f] for f in fields if f in nested}

    # Suricata 8의 dns 이벤트는 v3 포맷(queries[]/answers[])로도 나온다 — rrname 하나로 정규화
    if prefix == "suricata-dns":
        dns = event.get("dns") or {}
        if "rrname" not in doc.get("dns", {}):
            queries = dns.get("queries") or []
            if queries:
                doc["dns"] = {
                    **doc.get("dns", {}),
                    "rrname": queries[0].get("rrname"),
                    "rrtype": queries[0].get("rrtype"),
                }
            if "rcode" in dns:
                doc["dns"]["rcode"] = dns["rcode"]
            if "answers" in dns:
                doc["dns"]["answers_count"] = len(dns["answers"])
    return prefix, doc


def index_name_for(prefix: str, timestamp: str) -> str:
    """일 단위 인덱스(`suricata-flow-2026.10.03`). 템플릿 패턴 `<prefix>-*`에 걸린다."""
    ts = parse_eve_timestamp(timestamp)
    return f"{prefix}-{ts.astimezone(datetime.timezone.utc):%Y.%m.%d}"


def parse_eve_timestamp(value: str) -> datetime.datetime:
    # eve: "2026-09-01T23:04:53.158271+0900" — 오프셋에 콜론이 없어서 fromisoformat이 3.11에서 받는다
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def shift_timestamps_to_now(docs: Iterable[tuple[str, dict]],
                            now: datetime.datetime | None = None) -> list[tuple[str, dict]]:
    """문서들의 시간 간격은 유지하면서 가장 늦은 이벤트가 `now`가 되도록 전부 평행이동한다.

    과거에 캡처한 pcap을 "지금 막 들어온 트래픽"처럼 스케줄러의 최근 윈도우에 넣기 위한 용도.
    """
    docs = list(docs)
    if not docs:
        return docs
    now = now or datetime.datetime.now(datetime.timezone.utc)
    latest = max(parse_eve_timestamp(d["@timestamp"]) for _, d in docs)
    delta = now - latest
    shifted = []
    for prefix, doc in docs:
        ts = parse_eve_timestamp(doc["@timestamp"]) + delta
        shifted.append((prefix, {**doc, "@timestamp": ts.isoformat()}))
    return shifted


# ---- nginx access log ----------------------------------------------------------

# nginx 기본 "combined" 포맷 (docker nginx:alpine 기본값)
_NGINX_COMBINED_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def parse_nginx_access_line(line: str) -> dict | None:
    """combined 포맷 한 줄을 nginx-access 문서로 바꾼다. 못 파싱하면 None."""
    match = _NGINX_COMBINED_RE.match(line.strip())
    if match is None:
        return None
    ts = datetime.datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z")
    path = match.group("path")
    return {
        "@timestamp": ts.isoformat(),
        "src_ip": match.group("src_ip"),
        "event_type": "nginx-access",
        "nginx": {
            "path": path.split("?", 1)[0],
            "status": int(match.group("status")),
            "method": match.group("method"),
            "user_agent": match.group("user_agent"),
            "raw_line": line.strip(),
        },
    }


def nginx_lines_to_documents(lines: Iterable[str]) -> Iterator[tuple[str, dict]]:
    for line in lines:
        doc = parse_nginx_access_line(line)
        if doc is not None:
            yield "nginx-access", doc


# ---- ES 적재 -----------------------------------------------------------------------


async def bulk_index_documents(client: AsyncElasticsearch, docs: Iterable[tuple[str, dict]],
                               refresh: bool = True) -> dict[str, int]:
    """(접두사, 문서) 목록을 일 단위 인덱스에 bulk 적재하고 인덱스별 건수를 돌려준다."""
    actions = []
    counts: dict[str, int] = {}
    for prefix, doc in docs:
        index = index_name_for(prefix, doc["@timestamp"])
        actions.append({"_index": index, "_source": doc})
        counts[index] = counts.get(index, 0) + 1
    if actions:
        await async_bulk(client, actions)
        if refresh:
            await client.indices.refresh(index=",".join(counts))
    return counts
