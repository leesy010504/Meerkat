"""검증 통과 룰의 로컬 파일 배포(rules/<group>.rules + 제안서)와 PR 플로우를 검증한다."""

import datetime
import subprocess

import pytest

from meerkat.mcp_server.tools.deploy import (
    create_deploy_pr,
    deploy_rule_to_files,
    render_proposal,
    write_rule_to_group_file,
)
from meerkat.storage.rule_memory import RuleItem

NOW = datetime.datetime(2026, 10, 3, 12, 0, tzinfo=datetime.timezone.utc)


def _item(sid=1000010, rev=1, text=None, group="scanning", rationale="관계 판단: 신규 유형 — 포트 스캔"):
    return RuleItem(
        sid=sid, rev=rev, role_group=group, repr_event_ids=["evt-1", "evt-2"], repr_pcap_path=None,
        created_at=NOW, updated_at=NOW, origin="generated", rationale=rationale,
        rule_text=text or (
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"scan"; flow:to_server; '
            f"threshold:type threshold, track by_src, count 70, seconds 60; classtype:attempted-recon; sid:{sid}; rev:{rev};)"
        ),
    )


def test_new_rule_is_appended_without_touching_other_lines(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    existing = 'alert tcp any any -> any any (msg:"keep me"; sid:1000001; rev:1;)\n# a comment\n'
    (rules_dir / "scanning.rules").write_text(existing)

    path, replaced = write_rule_to_group_file(_item(), rules_dir)

    assert path == rules_dir / "scanning.rules" and replaced is False
    content = path.read_text()
    assert content.startswith(existing)  # 기존 줄·주석은 그대로
    assert content.count("sid:1000010;") == 1 and content.endswith("\n")


def test_repaired_rule_replaces_same_sid_line_in_place(tmp_path):
    rules_dir = tmp_path / "rules"
    write_rule_to_group_file(_item(rev=1), rules_dir)
    write_rule_to_group_file(_item(sid=1000011), rules_dir)

    path, replaced = write_rule_to_group_file(_item(rev=2), rules_dir)

    lines = path.read_text().splitlines()
    assert replaced is True
    assert len(lines) == 2
    assert "sid:1000010; rev:2;" in lines[0]  # 순서 유지, 리비전만 교체
    assert "sid:1000011;" in lines[1]


def test_commented_out_same_sid_is_not_treated_as_live_rule(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "scanning.rules").write_text('# alert tcp any any -> any any (sid:1000010; rev:1;)\n')

    path, replaced = write_rule_to_group_file(_item(), rules_dir)

    assert replaced is False
    assert path.read_text().splitlines()[0].startswith("#")  # 사람이 비활성화한 줄은 되살리지 않는다


def test_file_deploy_writes_proposal_with_rationale_and_evidence(tmp_path):
    result = deploy_rule_to_files(
        _item(), tmp_path / "rules", tmp_path / "proposals", metric="unique_dst_ports_per_src", src_ip="10.0.0.9"
    )
    proposal = open(result.proposal_file, encoding="utf-8").read()
    assert "sid:1000010 rev:1" in proposal and "`scanning`" in proposal
    assert "관계 판단: 신규 유형 — 포트 스캔" in proposal
    assert "`evt-1`" in proposal and "`evt-2`" in proposal
    assert "unique_dst_ports_per_src" in proposal and "10.0.0.9" in proposal
    assert "suricatasc -c reload-rules" in proposal
    assert (tmp_path / "rules" / "scanning.rules").exists()


def test_render_proposal_handles_missing_rationale():
    text = render_proposal(_item(rationale=None))
    assert "(기록 없음)" in text


@pytest.mark.asyncio
async def test_create_deploy_pr_commits_rule_on_new_branch_in_scratch_repo(tmp_path):
    """임시 git 레포에서 브랜치 생성·커밋까지 되는지 확인한다. gh pr create는 원격이 없어 실패하지만
    그 실패가 결과에 정직하게 담겨야 한다."""
    repo = tmp_path / "rules-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "rules").mkdir()
    (repo / "rules" / "scanning.rules").write_text("# existing\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)

    item = _item()
    result = await create_deploy_pr(
        item.rule_text, item.sid, item.role_group, rationale="근거", evidence_event_ids=["e1"],
        deployment_guide="가이드", rules_dir="rules", repo_dir=str(repo),
    )

    assert result.branch.startswith("meerkat/add-rule-1000010-")
    head = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo, capture_output=True, text=True)
    assert head.stdout.strip() == result.branch
    log = subprocess.run(["git", "log", "-1", "--pretty=%s"], cwd=repo, capture_output=True, text=True)
    assert log.stdout.strip() == "Add rule sid:1000010 to scanning"
    assert "sid:1000010;" in (repo / "rules" / "scanning.rules").read_text()
    assert result.ok is False and result.pr_url is None  # 원격 없음 → gh 실패가 그대로 보고됨
