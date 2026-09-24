"""생성된 룰이 올바른 역할 그룹에 매핑되고, 부정합 시 거부되는지 검증한다."""

import pytest

from meerkat.validation.logic_check import (
    check_rule_logic,
    load_role_groups,
    propose_role_groups,
)

SCAN_RULE = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any '
    '(msg:"port scan"; flow:to_server; '
    "threshold:type threshold, track by_src, count 70, seconds 60; "
    "classtype:attempted-recon; sid:1000001; rev:1;)"
)

WEB_ATTACK_RULE = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
    '(msg:"sqli attempt"; http.uri; content:"union select"; nocase; '
    "classtype:web-application-attack; sid:1000002; rev:1;)"
)

WRONG_CLASSTYPE_RULE = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any '
    '(msg:"mislabeled"; flow:to_server; '
    "threshold:type threshold, track by_src, count 70, seconds 60; "
    "classtype:web-application-attack; sid:1000003; rev:1;)"
)

WRONG_DIRECTION_RULE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
    '(msg:"backwards"; flow:to_server; '
    "threshold:type threshold, track by_src, count 70, seconds 60; "
    "classtype:attempted-recon; sid:1000004; rev:1;)"
)

DNS_FLOOD_RULE = (
    'alert udp $EXTERNAL_NET any -> $HOME_NET 53 '
    '(msg:"dns query flood"; '
    "threshold:type threshold, track by_src, count 500, seconds 60; "
    "classtype:denial-of-service; sid:1000005; rev:1;)"
)


@pytest.fixture(scope="module")
def role_groups():
    return load_role_groups("config/role_groups.yaml")


def test_scan_rule_matches_scanning_group(role_groups):
    result = check_rule_logic(SCAN_RULE, "scanning", role_groups)
    assert result.ok, result.reasons


def test_web_attack_rule_matches_web_attack_group(role_groups):
    result = check_rule_logic(WEB_ATTACK_RULE, "web-attack", role_groups)
    assert result.ok, result.reasons


def test_scan_rule_rejected_for_web_attack_group(role_groups):
    result = check_rule_logic(SCAN_RULE, "web-attack", role_groups)
    assert not result.ok
    assert result.reasons


def test_wrong_classtype_rejected(role_groups):
    result = check_rule_logic(WRONG_CLASSTYPE_RULE, "scanning", role_groups)
    assert not result.ok
    assert any("classtype" in reason for reason in result.reasons)


def test_wrong_direction_rejected(role_groups):
    result = check_rule_logic(WRONG_DIRECTION_RULE, "scanning", role_groups)
    assert not result.ok
    assert any("direction" in reason for reason in result.reasons)


def test_unknown_group_rejected(role_groups):
    result = check_rule_logic(SCAN_RULE, "nonexistent-group", role_groups)
    assert not result.ok


def test_propose_role_groups_ranks_scanning_first(role_groups):
    candidates = propose_role_groups(SCAN_RULE, role_groups)
    assert candidates and candidates[0] == "scanning"


def test_propose_role_groups_ranks_web_attack_first(role_groups):
    candidates = propose_role_groups(WEB_ATTACK_RULE, role_groups)
    assert candidates and candidates[0] == "web-attack"


def test_propose_role_groups_rejects_keyword_only_match(role_groups):
    """threshold 키워드만 우연히 겹친다고 protocol/classtype이 안 맞는 그룹에
    배정되면 안 된다 (SSH 브루트포스가 scanning으로 잘못 분류되던 버그)."""
    ssh_bruteforce_rule = (
        "alert tcp any any -> any 22 "
        '(msg:"ssh auth brute force"; flow:to_server; flags:S; '
        "threshold:type threshold, track by_src, count 1, seconds 60; "
        "classtype:attempted-admin; sid:1000006; rev:1;)"
    )
    candidates = propose_role_groups(ssh_bruteforce_rule, role_groups)
    assert candidates == []


def test_dns_flood_rule_matches_dns_flood_group(role_groups):
    result = check_rule_logic(DNS_FLOOD_RULE, "dns-flood", role_groups)
    assert result.ok, result.reasons


def test_non_dns_udp_dos_rejected_from_dns_flood_group(role_groups):
    """dns-flood는 protocol=udp + classtype=denial-of-service만으로 정의돼 있으면
    NTP 등 DNS와 무관한 UDP 증폭 공격까지 흡수한다 — "53"/"dns" 키워드 요건으로
    막아야 한다."""
    ntp_amplification_rule = (
        'alert udp $EXTERNAL_NET any -> $HOME_NET 123 (msg:"ntp monlist amplification"; '
        "classtype:denial-of-service; sid:1000007; rev:1;)"
    )
    assert propose_role_groups(ntp_amplification_rule, role_groups) == []
    result = check_rule_logic(ntp_amplification_rule, "dns-flood", role_groups)
    assert not result.ok
    assert any("keyword" in reason for reason in result.reasons)


def test_numeric_keyword_does_not_match_as_substring_of_sid(role_groups):
    """expected_keywords의 숫자(포트) 키워드는 헤더의 목적지 포트와 정확히
    일치할 때만 인정해야 한다 — sid가 253이면 "53"이 부분 문자열로 우연히
    포함돼 있다고 dns-flood로 잘못 분류되면 안 된다 (UDP/161 snmp reflection)."""
    snmp_reflection_rule = (
        'alert udp $EXTERNAL_NET any -> $HOME_NET 161 '
        '(msg:"snmp reflection dos"; classtype:denial-of-service; sid:253; rev:1;)'
    )
    assert propose_role_groups(snmp_reflection_rule, role_groups) == []


SSH_BRUTEFORCE_RULE = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET [22,2222] '
    '(msg:"ssh brute force"; flow:to_server; flags:S,12; '
    "threshold:type threshold, track by_src, count 10, seconds 60; "
    "classtype:attempted-admin; sid:1000006; rev:1;)"
)


def test_ssh_bruteforce_rule_lands_in_auth_bruteforce_not_scanning(role_groups):
    """threshold가 있어도 classtype이 attempted-admin이면 scanning이 아니라 auth-bruteforce다."""
    assert check_rule_logic(SSH_BRUTEFORCE_RULE, "auth-bruteforce", role_groups).ok
    assert not check_rule_logic(SSH_BRUTEFORCE_RULE, "scanning", role_groups).ok
    assert propose_role_groups(SSH_BRUTEFORCE_RULE, role_groups) == ["auth-bruteforce"]


def test_propose_role_groups_requires_inbound_direction(role_groups):
    """방향이 any/any로 뭉개진 룰은 폴백 후보에서도 빠져야 한다 — 안 그러면 LLM 후보가
    방향 불일치로 거부돼도 같은 그룹에 그대로 배정돼 검사가 무의미해진다."""
    any_any = SCAN_RULE.replace("$EXTERNAL_NET any -> $HOME_NET any", "any any -> any any")
    assert propose_role_groups(any_any, role_groups) == []
    assert propose_role_groups(WRONG_DIRECTION_RULE, role_groups) == []


def test_every_shipped_rule_file_matches_its_group_name(role_groups):
    """rules/<group>.rules 안의 모든 룰은 파일명이 가리키는 그룹 정의와 정합해야 한다."""
    from pathlib import Path

    checked = 0
    for path in Path("rules").glob("*.rules"):
        for line in path.read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            result = check_rule_logic(line, path.stem, role_groups)
            assert result.ok, f"{path.name}: {result.reasons}"
            checked += 1
    assert checked >= 3


def test_shipped_rules_trigger_only_on_their_own_attack_pcap():
    """룰 파일 각각이 자기 그룹 공격 pcap에서만 트리거되고 정상 코퍼스에선 조용해야 한다."""
    from pathlib import Path

    from meerkat.validation.replay import replay_rule

    expected = {
        # 저속 스캔·UA 위장 탐색은 같은 그룹의 어려운 변형이라 그 그룹 룰 파일에서 울려야 한다
        "scanning": {"port_scan.pcap", "slow_port_scan.pcap"},
        "web-attack": {"dir_bruteforce.pcap", "ua_spoofed_dirbust.pcap"},
        "auth-bruteforce": {"auth_bruteforce.pcap"},
        "dns-flood": {"dns_query_burst.pcap"},
    }
    attack = sorted(Path("pcaps/attack").glob("*.pcap"))
    benign = [str(p) for p in Path("pcaps/benign").glob("*.pcap")]
    for group, own in expected.items():
        rule = Path(f"rules/{group}.rules").read_text().strip()
        assert replay_rule(rule, "benign", benign).ok, f"{group} fires on benign"
        for pcap in attack:
            fired = not replay_rule(rule, "benign", [str(pcap)]).ok
            assert fired == (pcap.name in own), f"{group} on {pcap.name}: fired={fired}"


def test_response_side_rule_counts_as_inbound(role_groups):
    """404 폭증처럼 서버 응답을 보는 룰은 헤더가 HOME_NET → EXTERNAL_NET이어도 inbound 공격 탐지다."""
    rule = ('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"x"; flow:to_client,established; '
            'http.stat_code; content:"404"; classtype:web-application-attack; sid:9; rev:1;)')
    assert check_rule_logic(rule, "web-attack", role_groups).ok
    # 방향 키워드 없이 헤더만 뒤집힌 룰은 여전히 outbound로 본다
    outbound = rule.replace("flow:to_client,established; ", "")
    assert not check_rule_logic(outbound, "web-attack", role_groups).ok
