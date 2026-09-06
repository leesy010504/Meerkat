"""망가진 룰 20개에 대해 결정적 리라이트 결과를 검증한다."""

import pytest

from meerkat.validation.deterministic_fix import (
    apply_deterministic_fixes,
    check_sid_conflict,
)

# (설명, 망가진 룰, 이 리라이트가 반드시 적용되어야 하는지)
BROKEN_RULES = [
    (
        "legacy_http_modifier",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '(msg:"admin path"; content:"/admin"; http_uri; sid:1000001; rev:1;)',
        "legacy_http_modifier",
    ),
    (
        "tshark_field_misuse",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '(msg:"tshark field"; http.request.method; content:"POST"; sid:1000002; rev:1;)',
        "tshark_field_misuse",
    ),
    (
        "direction_conflict",
        'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
        '(msg:"backwards to_server"; flow:to_server; sid:1000003; rev:1;)',
        "direction_conflict",
    ),
    (
        "external_net_src_to_server",
        'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
        '(msg:"scan"; flow:to_server; threshold:type threshold, track by_src, count 70, seconds 60; '
        "sid:1000004; rev:1;)",
        "direction_conflict",
    ),
    (
        "dns_pcre_relative_flag",
        'alert udp $HOME_NET any -> any 53 '
        '(msg:"dns tunneling"; dns.query; pcre:"/^[a-f0-9]{32}$/R"; sid:1000005; rev:1;)',
        "dns_pcre_relative_flag",
    ),
    (
        "http_uri_endswith",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '(msg:"uri endswith"; http.uri; content:".php"; endswith; sid:1000006; rev:1;)',
        "http_uri_endswith",
    ),
    (
        "fast_pattern_without_content",
        'alert tcp any any -> any any (msg:"lone fast_pattern"; fast_pattern; sid:1000007; rev:1;)',
        "fast_pattern_without_content",
    ),
    (
        "bsize_mismatch",
        'alert tcp any any -> any any '
        '(msg:"bsize wrong"; content:"abcde"; bsize:3; sid:1000008; rev:1;)',
        "bsize_mismatch",
    ),
    (
        "nocase_without_content",
        'alert tcp any any -> any any (msg:"lone nocase"; nocase; sid:1000009; rev:1;)',
        "nocase_without_content",
    ),
    (
        "sticky_buffer_dup",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '(msg:"dup buffer"; http.uri; http.uri; content:"/x"; sid:1000010; rev:1;)',
        "sticky_buffer_dup",
    ),
    (
        "excessive_dns_pcre_anchor",
        'alert udp $HOME_NET any -> any 53 '
        '(msg:"anchored dns"; dns.query; pcre:"/^evil\\.example\\.com$/"; sid:1000011; rev:1;)',
        "excessive_dns_pcre_anchor",
    ),
    (
        "get_with_request_body",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '(msg:"GET with body"; http.method; content:"GET"; http.request_body; content:"x"; '
        "sid:1000012; rev:1;)",
        "get_with_request_body",
    ),
    (
        "to_server_with_response_buffer",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '(msg:"stat code wrong dir"; flow:to_server; http.stat_code; content:"500"; sid:1000013; rev:1;)',
        "to_server_with_response_buffer",
    ),
    (
        "tls_cert_field_with_client_direction",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 443 '
        '(msg:"cert wrong dir"; flow:to_server; tls.cert_subject; content:"CN=evil"; sid:1000014; rev:1;)',
        "tls_cert_field_with_client_direction",
    ),
    (
        "smb_ascii_match",
        'alert tcp any any -> any 445 '
        '(msg:"smb ascii"; app-layer-protocol:smb; content:"evil.exe"; sid:1000015; rev:1;)',
        "smb_ascii_match",
    ),
    (
        "invalid_threshold_syntax",
        'alert tcp any any -> any any '
        '(msg:"garbage threshold"; threshold:not a real clause; sid:1000016; rev:1;)',
        "invalid_threshold_syntax",
    ),
    (
        "multiple_patterns_combined",
        'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
        '(msg:"combo"; flow:to_server; content:"/admin"; http_uri; nocase; sid:1000017; rev:1;)',
        "legacy_http_modifier",  # 레거시 modifier + 방향 충돌이 동시에 낀 케이스 — 둘 다 고쳐져야 함
    ),
    (
        "already_valid_rule",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '(msg:"clean rule"; http.uri; content:"/admin"; sid:1000018; rev:1;)',
        None,  # 이미 정상 — 아무 리라이트도 적용되면 안 됨
    ),
    (
        "valid_threshold_rule",
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any '
        '(msg:"valid threshold"; flow:to_server; '
        "threshold:type threshold, track by_src, count 70, seconds 60; sid:1000019; rev:1;)",
        None,  # 이미 정상 threshold — 리라이트되면 안 됨
    ),
    (
        "duplicate_content_only_no_bug",
        'alert tcp any any -> any any (msg:"two contents"; content:"a"; content:"b"; sid:1000020; rev:1;)',
        None,  # 버그 없음 — 아무 리라이트도 적용되면 안 됨
    ),
]


@pytest.mark.parametrize("name,rule_text,expected_fix", BROKEN_RULES)
def test_deterministic_fix_applies_expected_pattern(name, rule_text, expected_fix):
    result = apply_deterministic_fixes(rule_text)
    if expected_fix is not None:
        assert expected_fix in result.applied_fixes, (
            f"{name}: expected '{expected_fix}' in {result.applied_fixes}"
        )
    else:
        assert result.applied_fixes == [], f"{name}: unexpected fixes {result.applied_fixes}"


def test_fix_rate_over_broken_subset():
    """고쳐져야 하는 케이스 대비 실제로 리라이트가 적용된 비율을 검증한다."""
    fixable = [(name, rt) for name, rt, expected in BROKEN_RULES if expected is not None]
    fixed_count = sum(1 for _, rt in fixable if apply_deterministic_fixes(rt).applied_fixes)
    rate = fixed_count / len(fixable)
    assert rate == 1.0, f"only {fixed_count}/{len(fixable)} fixable rules were actually fixed"


def test_combo_case_fixes_both_patterns():
    rule_text = (
        'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
        '(msg:"combo"; flow:to_server; content:"/admin"; http_uri; nocase; sid:1000017; rev:1;)'
    )
    result = apply_deterministic_fixes(rule_text)
    assert "legacy_http_modifier" in result.applied_fixes
    assert "direction_conflict" in result.applied_fixes


def test_sid_conflict_detection():
    rule_text = 'alert tcp any any -> any any (msg:"x"; sid:1000001; rev:1;)'
    assert check_sid_conflict(rule_text, {1000001, 2000000}) is True
    assert check_sid_conflict(rule_text, {2000000}) is False
