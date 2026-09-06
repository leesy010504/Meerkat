from meerkat.validation.syntax import check_rule_syntax

VALID_RULE = (
    'alert tcp any any -> any any '
    '(msg:"test rule"; sid:1000001; rev:1;)'
)

INVALID_RULE = (
    'alert tcp any any -> any any '
    '(msg:"broken rule"; sid:1000002)'
)


def test_valid_rule_passes():
    result = check_rule_syntax(VALID_RULE)
    assert result.ok


def test_invalid_rule_fails():
    result = check_rule_syntax(INVALID_RULE)
    assert not result.ok
