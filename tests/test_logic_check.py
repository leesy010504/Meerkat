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
