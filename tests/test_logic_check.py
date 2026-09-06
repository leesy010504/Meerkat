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
