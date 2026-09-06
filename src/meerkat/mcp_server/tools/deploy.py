import subprocess
import uuid
from pathlib import Path

from pydantic import BaseModel

from meerkat.validation.logic_check import RoleGroupDef, check_rule_logic, propose_role_groups


class PullRequestResult(BaseModel):
    branch: str
    pr_url: str | None
    ok: bool
    raw_output: str


def assign_role_group(
    rule_text: str, llm_candidate: str, role_groups: dict[str, RoleGroupDef]
) -> str:
    """LLM 후보를 규칙 기반으로 검증해 최종 역할 그룹을 확정한다."""
    result = check_rule_logic(rule_text, llm_candidate, role_groups)
    if result.ok:
        return llm_candidate

    candidates = propose_role_groups(rule_text, role_groups)
    if not candidates:
        raise ValueError(
            f"no role group matches this rule (LLM candidate '{llm_candidate}' rejected: {result.reasons})"
        )
    return candidates[0]


async def create_deploy_pr(
    rule_text: str,
    sid: int,
    role_group: str,
    rationale: str,
    evidence_event_ids: list[str],
    deployment_guide: str,
    rules_dir: str = "rules",
    repo_dir: str = ".",
) -> PullRequestResult:
    """rules/ 레포 체크아웃 안에서 실행한다고 가정하고 룰 파일을 커밋해 PR을 연다."""
    branch = f"meerkat/add-rule-{sid}-{uuid.uuid4().hex[:8]}"
    rule_file = Path(repo_dir) / rules_dir / f"{role_group}.rules"

    _run_git(["checkout", "-b", branch], cwd=repo_dir)

    rule_file.parent.mkdir(parents=True, exist_ok=True)
    with rule_file.open("a") as f:
        f.write(rule_text.strip() + "\n")

    _run_git(["add", str(rule_file)], cwd=repo_dir)
    commit_message = f"Add rule sid:{sid} to {role_group}"
    _run_git(["commit", "-m", commit_message], cwd=repo_dir)

    body = _pr_body(rationale, evidence_event_ids, deployment_guide)
    result = subprocess.run(
        ["gh", "pr", "create", "--title", commit_message, "--body", body],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )

    return PullRequestResult(
        branch=branch,
        pr_url=result.stdout.strip() if result.returncode == 0 else None,
        ok=result.returncode == 0,
        raw_output=result.stdout + result.stderr,
    )


def _run_git(args: list[str], cwd: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _pr_body(rationale: str, evidence_event_ids: list[str], deployment_guide: str) -> str:
    # 사람이 읽는 PR 본문을 만든다
    evidence = "\n".join(f"- {eid}" for eid in evidence_event_ids)
    return (
        f"## 판단 근거\n{rationale}\n\n"
        f"## 근거 이벤트\n{evidence}\n\n"
        f"## 배포 가이드\n{deployment_guide}\n"
    )
