from collections import defaultdict
from datetime import datetime

from pydantic import BaseModel


class AlertCluster(BaseModel):
    src_ip: str
    signature_id: int
    count: int
    first_seen: datetime
    last_seen: datetime
    representative_event_id: str
    event_ids: list[str]


def cluster_alerts(events: list[dict], window_seconds: int = 300) -> list[AlertCluster]:
    """src_ip + signature_id로 그룹화하고, 같은 그룹이어도 시간창을 넘어가면
    별개 클러스터로 다시 쪼갠다. 대표 샘플은 그룹의 중앙값 이벤트로 뽑는다."""
    groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for event in events:
        sid = event["alert"]["signature_id"]
        groups[(event["src_ip"], sid)].append(event)

    clusters: list[AlertCluster] = []
    for (src_ip, sid), group_events in groups.items():
        group_events.sort(key=lambda e: e["timestamp"])
        for window in _split_by_window(group_events, window_seconds):
            representative = window[len(window) // 2]
            clusters.append(
                AlertCluster(
                    src_ip=src_ip,
                    signature_id=sid,
                    count=len(window),
                    first_seen=_parse_ts(window[0]["timestamp"]),
                    last_seen=_parse_ts(window[-1]["timestamp"]),
                    representative_event_id=representative["_id"],
                    event_ids=[e["_id"] for e in window],
                )
            )
    return clusters


def _split_by_window(sorted_events: list[dict], window_seconds: int) -> list[list[dict]]:
    if not sorted_events:
        return []

    windows: list[list[dict]] = [[sorted_events[0]]]
    window_start = _parse_ts(sorted_events[0]["timestamp"])

    for event in sorted_events[1:]:
        ts = _parse_ts(event["timestamp"])
        if (ts - window_start).total_seconds() <= window_seconds:
            windows[-1].append(event)
        else:
            windows.append([event])
            window_start = ts

    return windows


def _parse_ts(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
