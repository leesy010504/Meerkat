import shutil

import pytest

from meerkat.agent.orchestrator import _repair_context
from meerkat.validation.traffic_profile import _max_in_window, _profile_events, traffic_contrast


def test_max_in_window_is_sliding():
    times = [0, 10, 20, 61, 62, 63, 64]
    assert _max_in_window(times, 60) == 6  # 10~64초 구간 (0은 64초와 60초 이상 떨어짐)


def _flow(src, port, start, tc="14", pkts=1):
    return {"event_type": "flow", "proto": "TCP", "src_ip": src, "dest_port": port, "timestamp": start,
            "flow": {"start": start, "pkts_toserver": pkts}, "tcp": {"tcp_flags_tc": tc}}


def test_profile_counts_refused_connections_of_the_busiest_source():
    events = [_flow("10.0.0.9", p, f"2026-10-14T00:00:{p:02d}+00:00") for p in range(1, 11)]
    events.append(_flow("10.0.0.1", 443, "2026-10-14T00:00:00+00:00", tc="1b", pkts=7))
    prof = _profile_events(events)
    assert prof["tcp_flows_from_top_src"] == 10
    assert prof["distinct_dest_ports"] == 10
    assert prof["refused_by_rst_ratio"] == 1.0
    assert "http_requests" not in prof


def test_profile_reports_http_404_rate():
    events = [_flow("10.0.0.9", 80, "2026-10-14T00:00:00+00:00", tc="1b", pkts=9)]
    for i in range(10):
        events.append({"event_type": "http", "timestamp": f"2026-10-14T00:00:{i:02d}+00:00",
                       "http": {"status": 404 if i < 8 else 200}})
    prof = _profile_events(events)
    assert prof["http_404_ratio"] == 0.8
    assert prof["max_http_404_per_60s"] == 8


@pytest.mark.skipif(shutil.which("suricata") is None, reason="suricata not installed")
def test_contrast_separates_slow_scan_from_browsing():
    contrast = traffic_contrast(["pcaps/attack/slow_port_scan.pcap"], ["pcaps/benign/web_browsing.pcap"], "suricata")
    attack, benign = contrast["attack"][0], contrast["must_stay_quiet_on"][0]
    assert attack["refused_by_rst_ratio"] == 1.0 and benign["refused_by_rst_ratio"] == 0.0
    # 분당 연결 수는 공격(60)이 정상 브라우징(140)보다 낮다 — count 조정만으로는 못 가르는 시나리오
    assert attack["max_tcp_flows_per_60s"] < benign["max_tcp_flows_per_60s"]


def test_repair_context_carries_history_and_skips_contrast_for_syntax():
    history = [{"rule_text": "alert tcp any any -> any any (sid:1;)", "failure": "no_trigger"}]
    ctx = _repair_context("syntax", "syntax:boom", {}, contrast_pcaps=([], [], "suricata"), history=history)
    assert "traffic_contrast" not in ctx
    assert ctx["previous_attempts"] == history
