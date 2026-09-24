"""검증 코퍼스(매니페스트), 재생 캐시, threshold 재생 보정."""

import shutil
import time
from pathlib import Path

import pytest


from meerkat.validation import replay as replay_module
from meerkat.validation.corpus import build_verify_context, load_manifest, pcaps_for_group
from meerkat.validation.replay import clear_replay_cache, replay_rule
from meerkat.validation.threshold_calibrate import (
    calibrate_threshold,
    extract_threshold_count,
    set_threshold_count,
)

SCAN = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"scan"; flow:to_server; flags:S,12; '
    "threshold:type threshold, track by_src, count {n}, seconds 300; classtype:attempted-recon; sid:1000000; rev:1;)"
)


# ---- corpus ---------------------------------------------------------------------------------


def test_manifest_covers_every_shipped_attack_pcap():
    manifest = load_manifest("pcaps/attack")
    on_disk = {p.name for p in Path("pcaps/attack").glob("*.pcap")}
    assert set(manifest) == on_disk
    assert {m["role_group"] for m in manifest.values()} == {"scanning", "web-attack", "auth-bruteforce", "dns-flood"}


def test_verify_context_splits_positive_and_cross_group_negative():
    ctx = build_verify_context("scanning", "pcaps/attack", "pcaps/benign")
    assert ctx.attack_pcaps == ["pcaps/attack/port_scan.pcap", "pcaps/attack/slow_port_scan.pcap"]
    benign = {p for p in ctx.benign_pcaps if p.startswith("pcaps/benign/")}
    negatives = {p for p in ctx.benign_pcaps if p.startswith("pcaps/attack/")}
    assert len(benign) == len(list(Path("pcaps/benign").glob("*.pcap")))
    assert negatives == {"pcaps/attack/dir_bruteforce.pcap", "pcaps/attack/auth_bruteforce.pcap",
                         "pcaps/attack/dns_query_burst.pcap", "pcaps/attack/ua_spoofed_dirbust.pcap"}
    assert pcaps_for_group("pcaps/attack", load_manifest("pcaps/attack"), "dns-flood") == ["pcaps/attack/dns_query_burst.pcap"]


def test_metric_beats_wrong_role_group_hint():
    """conn_count_per_src_port는 스케줄러가 "scanning"으로 힌트하지만 실제 pcap은 SSH 브루트포스다.
    지표 기준으로 positive를 잡아야 맞는 SSH 룰이 SSH pcap을 negative로 두고 떨어지지 않는다."""
    ctx = build_verify_context("scanning", "pcaps/attack", "pcaps/benign", metric="conn_count_per_src_port")
    assert ctx.attack_pcaps == ["pcaps/attack/auth_bruteforce.pcap"]
    assert "pcaps/attack/auth_bruteforce.pcap" not in ctx.benign_pcaps
    assert "pcaps/attack/port_scan.pcap" in ctx.benign_pcaps  # 다른 그룹 → negative

    # 매니페스트에 없는 지표면 역할 그룹 힌트로 폴백
    ctx = build_verify_context("scanning", "pcaps/attack", "pcaps/benign", metric="request_rate_per_src")
    assert ctx.attack_pcaps == ["pcaps/attack/port_scan.pcap", "pcaps/attack/slow_port_scan.pcap"]


def test_scheduler_context_uses_triggering_metric():
    from meerkat.agent.orchestrator import VerifyContext
    from meerkat.agent.scheduler import SchedulerConfig, _verify_context_for

    config = SchedulerConfig(pcaps_attack_dir="pcaps/attack", pcaps_benign_dir="pcaps/benign")
    ctx = _verify_context_for("scanning", VerifyContext([], []), None, config, "conn_count_per_src_port")
    assert ctx.attack_pcaps == ["pcaps/attack/auth_bruteforce.pcap"]


def test_verify_context_falls_back_when_group_has_no_pcaps(tmp_path):
    ctx = build_verify_context("unknown-group", "pcaps/attack", "pcaps/benign")
    assert len(ctx.attack_pcaps) == len(list(Path("pcaps/attack").glob("*.pcap")))  # 전부 positive
    assert all(p.startswith("pcaps/benign/") for p in ctx.benign_pcaps)  # 교차 negative 없음

    empty = tmp_path / "attack"
    empty.mkdir()
    ctx = build_verify_context("scanning", empty, "pcaps/benign", repr_pcap="/x/live.pcap")
    assert ctx.attack_pcaps == ["/x/live.pcap"]  # 매니페스트 없음 + 대표 pcap만


def test_repr_pcap_is_added_to_positives_once():
    ctx = build_verify_context("scanning", "pcaps/attack", "pcaps/benign", repr_pcap="pcaps/attack/port_scan.pcap")
    assert ctx.attack_pcaps == ["pcaps/attack/port_scan.pcap", "pcaps/attack/slow_port_scan.pcap"]
    ctx = build_verify_context("scanning", "pcaps/attack", "pcaps/benign", repr_pcap="/live/x.pcap")
    assert ctx.attack_pcaps[-1] == "/live/x.pcap"


# ---- replay cache -----------------------------------------------------------------------------


def test_replay_cache_skips_suricata_on_repeat_and_flips_target(monkeypatch):
    clear_replay_cache()
    runs = {"n": 0}
    real = replay_module._replay_rule_uncached

    def counting(*args, **kwargs):
        runs["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(replay_module, "_replay_rule_uncached", counting)
    rule = SCAN.format(n=200)
    first = replay_rule(rule, "attack", ["pcaps/attack/port_scan.pcap"])
    t0 = time.perf_counter()
    second = replay_rule(rule, "benign", ["pcaps/attack/port_scan.pcap"])  # 같은 입력, 다른 target
    elapsed = time.perf_counter() - t0
    assert runs["n"] == 1 and elapsed < 0.05
    assert first.ok is True and second.ok is False  # attack 기준 통과 == benign 기준 실패
    assert first.triggered_sids == second.triggered_sids == [1000000]


def test_replay_cache_invalidates_when_pcap_changes(monkeypatch, tmp_path):
    clear_replay_cache()
    runs = {"n": 0}
    real = replay_module._replay_rule_uncached

    def counting(*args, **kwargs):
        runs["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(replay_module, "_replay_rule_uncached", counting)
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(Path("pcaps/benign/normal_traffic.pcap").read_bytes())
    rule = SCAN.format(n=200)
    replay_rule(rule, "benign", [str(pcap)])
    replay_rule(rule, "benign", [str(pcap)])
    assert runs["n"] == 1
    pcap.write_bytes(Path("pcaps/benign/web_browsing.pcap").read_bytes())  # 내용·크기 변경
    replay_rule(rule, "benign", [str(pcap)])
    assert runs["n"] == 2


# ---- threshold calibration ----------------------------------------------------------------------


def test_count_helpers():
    assert extract_threshold_count(SCAN.format(n=37)) == 37
    assert extract_threshold_count('alert tcp any any -> any any (msg:"x"; sid:1;)') is None
    df = 'alert tcp any any -> any any (detection_filter:track by_src, count 5, seconds 60; sid:1;)'
    assert extract_threshold_count(df) == 5 and "count 12," in set_threshold_count(df, 12)
    # msg 안의 "count"는 건드리지 않는다
    tricky = 'alert tcp any any -> any any (msg:"count 1"; threshold:type threshold, track by_src, count 3, seconds 1; sid:1;)'
    assert extract_threshold_count(tricky) == 3 and 'msg:"count 1"' in set_threshold_count(tricky, 9)


def test_calibration_raises_count_until_negatives_are_quiet_but_attack_still_fires():
    negatives = ["pcaps/benign/web_browsing.pcap", "pcaps/benign/ssh_normal.pcap", "pcaps/attack/auth_bruteforce.pcap"]
    result = calibrate_threshold(SCAN.format(n=30), ["pcaps/attack/port_scan.pcap"], negatives)
    assert result is not None and result.changed
    assert 30 < result.calibrated_count <= 30 * 8
    # 최소성: 한 단계 아래 count는 negative에서 울린다
    below = set_threshold_count(result.rule_text, result.calibrated_count - 1)
    assert not replay_rule(below, "benign", negatives).ok
    assert replay_rule(result.rule_text, "benign", negatives).ok
    assert replay_rule(result.rule_text, "attack", ["pcaps/attack/port_scan.pcap"]).ok


def test_calibration_is_noop_when_already_quiet_and_none_for_non_rate_rules():
    quiet = calibrate_threshold(SCAN.format(n=200), ["pcaps/attack/port_scan.pcap"], ["pcaps/benign/web_browsing.pcap"])
    assert quiet is not None and not quiet.changed and quiet.replays == 1
    content_rule = 'alert http any any -> any any (msg:"x"; http.user_agent; content:"gobuster"; sid:1;)'
    assert calibrate_threshold(content_rule, ["pcaps/attack/dir_bruteforce.pcap"], ["pcaps/benign/web_browsing.pcap"]) is None


def test_calibration_gives_up_when_attack_and_negative_cannot_be_separated():
    # auth_bruteforce.pcap(13 SYN)을 공격으로, port_scan.pcap(65k SYN)을 negative로 두면
    # negative를 조용하게 만드는 count에서는 공격이 절대 안 울린다 → None
    result = calibrate_threshold(SCAN.format(n=5), ["pcaps/attack/auth_bruteforce.pcap"], ["pcaps/attack/port_scan.pcap"])
    assert result is None


def test_calibration_refuses_huge_multipliers_so_llm_can_fix_what_is_counted():
    """모든 패킷을 세는 룰(flags:S 없음)은 count를 수십 배 올려야 정상 트래픽이 조용해진다 — 그건 count가 아니라
    세는 대상이 틀린 것이니 보정을 포기(None)하고 LLM 수리로 넘겨야 한다. (실측 60→1680 사례)"""
    all_packets = SCAN.replace(" flags:S,12;", "").format(n=60)
    negatives = ["pcaps/benign/web_browsing.pcap", "pcaps/benign/ssh_normal.pcap"]
    assert calibrate_threshold(all_packets, ["pcaps/attack/port_scan.pcap"], negatives) is None


@pytest.mark.skipif(shutil.which("suricata") is None, reason="suricata not installed")
def test_replay_respects_threshold_window_on_slow_scan():
    """저속 스캔(분당 패킷 ~120개)에서 60초 창 threshold가 정확해야 한다.
    autofp 멀티스레드 리플레이에서는 count 280도 울려서 threshold 룰 판정이 틀렸다."""
    from meerkat.validation.replay import _replay_rule_uncached

    def fires(count: int) -> bool:
        rule = (f'alert tcp any any -> any any (msg:"x"; threshold:type threshold, track by_src, '
                f'count {count}, seconds 60; sid:1; rev:1;)')
        return bool(_replay_rule_uncached(rule, "attack", ["pcaps/attack/slow_port_scan.pcap"]).triggered_sids)

    assert fires(100)
    for _ in range(3):
        assert not fires(130)
        assert not fires(280)


@pytest.mark.skipif(shutil.which("suricata") is None, reason="suricata not installed")
def test_separation_widens_window_for_slow_scan():
    """저속 스캔: 60초 창에선 공격(분당 60) < 정상 브라우징(분당 140)이라 가를 수 없고, 300초 창에선 갈린다."""
    from meerkat.validation.threshold_calibrate import find_separating_threshold

    rule = ('alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"x"; flow:to_server; flags:S; '
            'detection_filter:track by_src, count 210, seconds 60; sid:1000000; rev:1;)')
    negatives = [str(p) for p in Path("pcaps/benign").glob("*.pcap")]
    result = find_separating_threshold(rule, ["pcaps/attack/slow_port_scan.pcap"], negatives)
    assert result is not None and result.seconds == 300
    assert result.negative_max < result.count <= result.attack_max  # 정상 수준 위, 공격 수준 이하
    assert replay_rule(result.rule_text, "attack", ["pcaps/attack/slow_port_scan.pcap"]).ok
    assert replay_rule(result.rule_text, "benign", negatives).ok


@pytest.mark.skipif(shutil.which("suricata") is None, reason="suricata not installed")
def test_separation_gives_up_when_rule_counts_the_wrong_thing():
    """모든 패킷을 세는 룰은 어떤 창·count로도 정상 브라우징과 안 갈린다 → None (LLM이 flags:S 등을 고칠 몫)."""
    from meerkat.validation.threshold_calibrate import find_separating_threshold

    rule = ('alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"x"; flow:to_server; '
            'detection_filter:track by_src, count 210, seconds 60; sid:1000000; rev:1;)')
    negatives = [str(p) for p in Path("pcaps/benign").glob("*.pcap")]
    assert find_separating_threshold(rule, ["pcaps/attack/slow_port_scan.pcap"], negatives) is None
