"""커뮤니티 룰셋 임포트의 핵심 동작(alert만/분류 엄격함/sid 충돌 스킵)을 검증한다."""

import pytest

from meerkat.storage.rule_memory import RuleItem, RuleMemory

from scripts.import_community_rules import (
    classify_strict,
    extract_sid,
    is_alert_action,
    import_rules,
)
from meerkat.validation.logic_check import load_role_groups


def test_is_alert_action():
    assert is_alert_action('alert tcp any any -> any any (sid:1;)')
    assert not is_alert_action('drop tcp any any -> any any (sid:1;)')
    assert not is_alert_action('reject tcp any any -> any any (sid:1;)')


def test_extract_sid():
    assert extract_sid('alert tcp any any -> any any (msg:"x"; sid:2010001; rev:1;)') == 2010001
    assert extract_sid('alert tcp any any -> any any (msg:"no sid";)') is None


def test_classify_strict_matches_known_classtype():
    role_groups = load_role_groups()
    scan_rule = (
        'alert tcp any any -> any any (msg:"x"; classtype:attempted-recon; sid:1;)'
    )
    web_rule = (
        'alert http any any -> any any (msg:"x"; classtype:web-application-attack; sid:2;)'
    )
    unknown_rule = (
        'alert tcp any any -> any any (msg:"x"; classtype:protocol-command-decode; sid:3;)'
    )

    assert classify_strict(scan_rule, role_groups) == "scanning"
    assert classify_strict(web_rule, role_groups) == "web-attack"
    assert classify_strict(unknown_rule, role_groups) is None


@pytest.mark.asyncio
async def test_import_rules_filters_and_classifies(tmp_path, monkeypatch):
    rules_file = tmp_path / "community.rules"
    rules_file.write_text(
        "\n".join(
            [
                "# comment line, should be skipped",
                "",
                'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB good one"; '
                'classtype:web-application-attack; sid:2010001; rev:1;)',
                'drop tcp any any -> any any (msg:"drop rule, must be excluded"; '
                'classtype:attempted-recon; sid:2010002; rev:1;)',
                'alert tcp any any -> any any (msg:"decoder event, unclassified"; '
                'classtype:protocol-command-decode; sid:2010003; rev:1;)',
                'alert tcp any any -> any any (msg:"scan rule"; '
                'classtype:network-scan; sid:2010004; rev:1;)',
                'alert tcp any any -> any any (msg:"no sid, must be excluded"; '
                "classtype:attempted-recon;)",
                'alert tcp any any -> any any (msg:"conflicts with local range"; '
                "classtype:attempted-recon; sid:1000005; rev:1;)",
            ]
        )
    )

    memory_path = tmp_path / ".meerkat" / "rule_memory.json"

    import scripts.import_community_rules as mod

    monkeypatch.setattr(mod, "RuleMemory", lambda: RuleMemory(path=memory_path))
    stats = await import_rules(str(rules_file))

    assert stats["total_lines"] == 6
    assert stats["not_alert"] == 1  # drop
    assert stats["no_sid"] == 1
    assert stats["sid_conflict"] == 1  # 1000005는 로컬 범위(1000000-1999999)
    assert stats["unclassified"] == 1  # protocol-command-decode
    assert stats["imported"] == 2  # web-application-attack + network-scan

    memory = RuleMemory(path=memory_path)
    items = await memory.list()
    by_sid = {i.sid: i for i in items}

    assert by_sid[2010001].role_group == "web-attack"
    assert by_sid[2010001].origin == "imported"
    assert by_sid[2010004].role_group == "scanning"
    assert 2010002 not in by_sid  # drop 룰은 절대 안 들어감
    assert 1000005 not in by_sid  # 로컬 범위 충돌
