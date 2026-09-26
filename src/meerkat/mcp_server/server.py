import os
from typing import Literal

from elasticsearch import AsyncElasticsearch

try:  # mcp 2.x: FastMCP → MCPServer (데코레이터 API는 동일)
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # pragma: no cover - mcp 1.x
    from mcp.server.fastmcp import FastMCP

from meerkat.config import Settings, load_settings
from meerkat.mcp_server.tools.deploy import (
    FileDeployResult,
    PullRequestResult,
    create_deploy_pr,
    deploy_rule_to_files,
    render_proposal,
)
from meerkat.mcp_server.tools.es_aggregate import (
    AggregateResult,
    MetricName,
    es_aggregate,
)
from meerkat.mcp_server.tools.es_query import IndexName, es_query_events
from meerkat.mcp_server.tools.rule_ops import rule_replay, rule_syntax_check
from meerkat.storage.failure_queue import FailureItem, FailureQueue
from meerkat.storage.rule_memory import RuleItem, RuleMemory
from meerkat.validation.deterministic_fix import (
    DeterministicFixResult,
    apply_deterministic_fixes,
)
from meerkat.validation.logic_check import (
    LogicCheckResult,
    check_rule_logic,
    load_role_groups,
    propose_role_groups,
)
from meerkat.validation.replay import ReplayResult
from meerkat.validation.syntax import SyntaxResult

settings: Settings = load_settings()
mcp = FastMCP("meerkat")

# ES 읽기 전용 계정을 쓰고 비밀번호는 환경변수로 받는다 (로컬 dev ES처럼 보안이 꺼져 있으면 비워둔다)
_es_client = AsyncElasticsearch(
    hosts=settings.elasticsearch.hosts,
    basic_auth=(
        (settings.elasticsearch.read_only_user, os.environ["MEERKAT_ES_PASSWORD"])
        if os.environ.get("MEERKAT_ES_PASSWORD")
        else None
    ),
)
_rule_memory = RuleMemory()
_failure_queue = FailureQueue()
_role_groups = load_role_groups()


@mcp.tool()
async def es_query_events_tool(
    index: IndexName,
    start: str,
    end: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    signature_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    return await es_query_events(
        _es_client, index, start, end, src_ip, dst_ip, dst_port, signature_id, limit
    )


@mcp.tool()
async def es_aggregate_tool(
    metric: MetricName,
    start: str,
    end: str,
    window_seconds: int,
    top_n: int = 20,
    compare_baseline: bool = True,
) -> AggregateResult:
    return await es_aggregate(
        _es_client, metric, start, end, window_seconds, top_n, compare_baseline
    )


@mcp.tool()
async def rule_syntax_check_tool(rule_text: str) -> SyntaxResult:
    return await rule_syntax_check(rule_text, settings.suricata.binary)


@mcp.tool()
async def rule_replay_tool(
    rule_text: str,
    target: Literal["attack", "benign"],
    pcap_paths: list[str] | None = None,
) -> ReplayResult:
    return await rule_replay(
        rule_text,
        target,
        pcap_paths,
        pcaps_attack_dir=settings.paths.pcaps_attack,
        pcaps_benign_dir=settings.paths.pcaps_benign,
        suricata_binary=settings.suricata.binary,
    )


@mcp.tool()
async def rule_memory_list_tool() -> list[RuleItem]:
    return await _rule_memory.list()


@mcp.tool()
async def rule_memory_get_tool(sid: int) -> RuleItem:
    return await _rule_memory.get(sid)


@mcp.tool()
async def rule_memory_upsert_tool(item: RuleItem) -> None:
    await _rule_memory.upsert(item)


@mcp.tool()
async def create_deploy_pr_tool(
    rule_text: str,
    sid: int,
    role_group: str,
    rationale: str,
    evidence_event_ids: list[str],
    deployment_guide: str,
) -> PullRequestResult:
    return await create_deploy_pr(
        rule_text, sid, role_group, rationale, evidence_event_ids, deployment_guide,
        rules_dir=settings.paths.rules_dir,
    )


@mcp.tool()
async def rule_deterministic_fix_tool(rule_text: str) -> DeterministicFixResult:
    """LLM 없이 고칠 수 있는 패턴(레거시 modifier, 방향 충돌, drop→alert 등)을 적용한 룰을 돌려준다."""
    return apply_deterministic_fixes(rule_text)


@mcp.tool()
async def rule_logic_check_tool(rule_text: str, role_group: str) -> LogicCheckResult:
    """룰이 주장하는 역할 그룹 정의(프로토콜/방향/classtype/특징 키워드)와 정합하는지 검사한다."""
    return check_rule_logic(rule_text, role_group, _role_groups)


@mcp.tool()
async def role_group_candidates_tool(rule_text: str) -> list[str]:
    """룰 내용만 보고 들어갈 수 있는 역할 그룹 후보를 규칙 기반으로 제시한다."""
    return propose_role_groups(rule_text, _role_groups)


@mcp.tool()
async def failure_queue_list_tool() -> list[FailureItem]:
    """검증 통과 룰을 만들지 못한 케이스와 LLM이 제안한 새 역할 그룹 후보 목록."""
    return await _failure_queue.list()


@mcp.tool()
async def render_deploy_proposal_tool(sid: int) -> str:
    """rule_memory의 룰 하나에 대한 사람이 읽는 배포 제안서(마크다운)를 만든다."""
    return render_proposal(await _rule_memory.get(sid))


@mcp.tool()
async def deploy_rule_to_files_tool(sid: int) -> FileDeployResult:
    """rule_memory의 룰을 rules/<role_group>.rules에 반영하고 제안서를 남긴다 (git은 건드리지 않는다)."""
    item = await _rule_memory.get(sid)
    return deploy_rule_to_files(item, settings.paths.rules_dir, settings.deploy.proposals_dir)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
