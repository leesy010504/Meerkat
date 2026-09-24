"""수리 프롬프트용 트래픽 프로파일 대조 — 공격 pcap과 정상(negative) pcap을 숫자로 비교한다.

threshold 룰 수리에서 소형 모델은 "count를 내리면 오탐, 올리면 미탐"을 오가다 K회를 다 쓴다
(저속 포트 스캔 실험). 모델에게 필요한 건 두 트래픽을 가르는 수치 근거다:
분당/5분당 최대 연결 수, 서버가 RST로 거절한 연결 비율, 고유 목적지 포트 수, HTTP 404 비율.

모든 값은 Suricata가 pcap에서 계산한 숫자다 — 공격자가 통제하는 문자열(URL, UA 등)은 한 글자도
넣지 않으므로 인젝션 필터를 거칠 필요가 없다.
"""

from __future__ import annotations

import datetime
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path

from meerkat.ingestion.eve_ingest import run_suricata_to_eve

_RST = 0x04
_WINDOWS = (60, 300)


def _ts(value: str) -> float:
    return datetime.datetime.fromisoformat(value).timestamp()


def _max_in_window(times: list[float], seconds: int) -> int:
    times = sorted(times)
    best, left = 0, 0
    for right, t in enumerate(times):
        while t - times[left] >= seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def _profile_events(events: list[dict]) -> dict | None:
    flows = [e for e in events if e.get("event_type") == "flow" and e.get("proto") == "TCP"]
    if not flows:
        return None
    by_src: dict[str, list[dict]] = defaultdict(list)
    for e in flows:
        by_src[e.get("src_ip", "")].append(e)
    src, src_flows = max(by_src.items(), key=lambda kv: len(kv[1]))

    refused = 0
    for e in src_flows:
        tcp = e.get("tcp") or {}
        try:
            tc = int(tcp.get("tcp_flags_tc", "0"), 16)
        except ValueError:
            tc = 0
        # 서버가 RST로 답하고 클라이언트가 데이터를 못 보낸 연결 = 닫힌 포트로 거절된 연결
        if tc & _RST and (e.get("flow") or {}).get("pkts_toserver", 0) <= 2:
            refused += 1
    times = [_ts((e.get("flow") or {}).get("start") or e["timestamp"]) for e in src_flows]

    http = [e for e in events if e.get("event_type") == "http"]
    status = Counter((e.get("http") or {}).get("status") for e in http)
    profile = {
        "tcp_flows_from_top_src": len(src_flows),
        **{f"max_tcp_flows_per_{w}s": _max_in_window(times, w) for w in _WINDOWS},
        "distinct_dest_ports": len({e.get("dest_port") for e in src_flows}),
        "refused_by_rst_ratio": round(refused / len(src_flows), 2),
    }
    if http:
        http_times = [_ts(e["timestamp"]) for e in http]
        not_found = [_ts(e["timestamp"]) for e in http if (e.get("http") or {}).get("status") == 404]
        profile.update({
            "http_requests": len(http),
            **{f"max_http_requests_per_{w}s": _max_in_window(http_times, w) for w in _WINDOWS},
            "http_404_ratio": round(status.get(404, 0) / len(http), 2),
            **{f"max_http_404_per_{w}s": _max_in_window(not_found, w) for w in _WINDOWS},
        })
    return profile


@lru_cache(maxsize=64)
def _profile_cached(pcap: str, mtime: float, size: int, binary: str) -> dict | None:
    return _profile_events(run_suricata_to_eve(pcap, binary))


def profile_pcap(pcap: str | Path, suricata_binary: str) -> dict | None:
    path = Path(pcap)
    if not path.exists():
        return None
    stat = path.stat()
    return _profile_cached(str(path), stat.st_mtime, stat.st_size, suricata_binary)


def traffic_contrast(attack_pcaps: list[str], negative_pcaps: list[str], suricata_binary: str) -> dict:
    """공격 pcap별 프로파일과 negative pcap별 프로파일을 나란히 준다.

    negative에는 정상 트래픽과 다른 계열 공격이 섞여 있어(포트 스캔 pcap의 연결 6만 개 등) 최댓값 하나로
    합치면 정상 브라우징 수준이 가려진다. 그래서 pcap 파일명(우리가 만든 코퍼스 이름, 공격자 통제 아님)별로 둔다.
    """
    attack = [{"pcap": Path(x).name, **prof} for x in attack_pcaps if (prof := profile_pcap(x, suricata_binary))]
    negatives = [{"pcap": Path(x).name, **prof} for x in negative_pcaps
                 if (prof := profile_pcap(x, suricata_binary))]
    return {
        "attack": attack,
        "must_stay_quiet_on": negatives,
        "note": "attack에서는 울리고 must_stay_quiet_on 전부에서는 조용해야 한다. 공격 값과 모든 negative 값 "
                "사이에 틈이 있는 지표가 둘을 가르는 신호다. *_per_60s/300s는 threshold seconds 창에 대응한다. "
                "refused_by_rst_ratio는 서버가 RST로 거절한 연결 비율(닫힌 포트 탐색), http_404_ratio는 "
                "존재하지 않는 경로 요청 비율이다.",
    }
