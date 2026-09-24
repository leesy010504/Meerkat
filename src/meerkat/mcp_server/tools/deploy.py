import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from meerkat.storage.rule_memory import RuleItem
from meerkat.validation.logic_check import (
    RoleGroupDef,
    check_rule_logic,
    propose_role_groups,
)

DEFAULT_DEPLOYMENT_GUIDE = (
    "1. 이 PR을 리뷰·승인하면 ArgoCD가 rules/ 디렉토리를 suricata-rules ConfigMap으로 동기화한다.\n"
    "2. Suricata DaemonSet 파드에서 `suricatasc -c reload-rules`로 룰을 재적재한다 "
    "(deploy/k8s/22-suricata-daemonset.yaml 참조).\n"
    "3. 배포 후 24시간 동안 해당 sid의 알럿량을 확인하고, 과다하면 PR을 revert한다 — "
    "에이전트는 룰을 비활성화하지 않는다."
)


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


# ---- 로컬 파일 배포 (GitOps 소스 디렉토리 갱신) ---------------------------------------------

_SID_RE = re.compile(r"\bsid:\s*(\d+)\s*;")


class FileDeployResult(BaseModel):
    rule_file: str
    proposal_file: str | None
    replaced_existing: bool  # 같은 sid의 이전 리비전을 교체했는지 (수리 배포)


def write_rule_to_group_file(item: RuleItem, rules_dir: str | Path) -> tuple[Path, bool]:
    """rules/<role_group>.rules에 룰을 넣는다. 같은 sid 줄이 있으면 교체, 없으면 끝에 추가.

    에이전트는 룰을 삭제·비활성화하지 않는다(§14) — 여기서도 다른 sid 줄은 절대 건드리지 않는다.
    """
    rules_dir = Path(rules_dir)
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rules_dir / f"{item.role_group}.rules"

    lines = rule_file.read_text().splitlines() if rule_file.exists() else []
    new_line = item.rule_text.strip()
    replaced = False
    out: list[str] = []
    for line in lines:
        match = _SID_RE.search(line)
        if match and int(match.group(1)) == item.sid and not line.lstrip().startswith("#"):
            if not replaced:
                out.append(new_line)
                replaced = True
            continue  # 같은 sid 중복 줄은 하나로
        out.append(line)
    if not replaced:
        out.append(new_line)

    rule_file.write_text("\n".join(out).rstrip("\n") + "\n")
    return rule_file, replaced


def render_proposal(item: RuleItem, metric: str | None = None, src_ip: str | None = None,
                    deployment_guide: str = DEFAULT_DEPLOYMENT_GUIDE,
                    trace_lines: list[str] | None = None) -> str:
    """사람이 읽는 배포 제안서(PR 본문과 같은 구조)를 마크다운으로 만든다."""
    evidence = "\n".join(f"- `{eid}`" for eid in item.repr_event_ids) or "- (없음)"
    trigger = ""
    if metric or src_ip:
        trigger = f"\n트리거: metric=`{metric}` src_ip=`{src_ip}`\n"
    verification = (
        "\n".join(f"- {line}" for line in trace_lines) if trace_lines else
        "- 문법 검사(suricata -T) 통과\n- 공격 재현 pcap에서 알럿 발생 확인\n"
        "- 정상 트래픽 pcap에서 알럿 없음 확인\n- 역할 그룹 정합성(프로토콜/방향/classtype) 통과"
    )
    return (
        f"# Rule sid:{item.sid} rev:{item.rev} → `{item.role_group}` ({item.origin})\n\n"
        f"생성 시각: {item.updated_at.isoformat()}{trigger}\n"
        f"```\n{item.rule_text.strip()}\n```\n\n"
        f"## 판단 근거\n{item.rationale or '(기록 없음)'}\n\n"
        f"## 근거 이벤트\n{evidence}\n\n"
        f"## 검증 과정\n{verification}\n"
        + (f"- 대표 pcap: `{item.repr_pcap_path}`\n" if item.repr_pcap_path else "")
        + f"\n## 배포 가이드\n{deployment_guide}\n"
    )


def deploy_rule_to_files(
    item: RuleItem,
    rules_dir: str | Path,
    proposals_dir: str | Path | None,
    metric: str | None = None,
    src_ip: str | None = None,
    trace_lines: list[str] | None = None,
) -> FileDeployResult:
    """검증을 통과한 룰을 GitOps 소스(rules/)에 반영하고 제안서를 남긴다. git은 건드리지 않는다."""
    rule_file, replaced = write_rule_to_group_file(item, rules_dir)
    proposal_file = None
    if proposals_dir is not None:
        proposals_dir = Path(proposals_dir)
        proposals_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        proposal_path = proposals_dir / f"{stamp}-sid{item.sid}-rev{item.rev}.md"
        proposal_path.write_text(render_proposal(item, metric, src_ip, trace_lines=trace_lines))
        proposal_file = str(proposal_path)
    return FileDeployResult(rule_file=str(rule_file), proposal_file=proposal_file, replaced_existing=replaced)
