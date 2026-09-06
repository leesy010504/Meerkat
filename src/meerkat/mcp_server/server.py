import os
from typing import Literal

from elasticsearch import AsyncElasticsearch
from mcp.server.fastmcp import FastMCP

from meerkat.config import Settings, load_settings
from meerkat.mcp_server.tools.deploy import PullRequestResult, create_deploy_pr
from meerkat.mcp_server.tools.es_aggregate import AggregateResult, MetricName, es_aggregate
from meerkat.mcp_server.tools.es_query import IndexName, es_query_events
from meerkat.mcp_server.tools.rule_ops import rule_replay, rule_syntax_check
from meerkat.storage.rule_memory import RuleItem, RuleMemory
from meerkat.validation.replay import ReplayResult
from meerkat.validation.syntax import SyntaxResult

settings: Settings = load_settings()
mcp = FastMCP("meerkat")

# ES 읽기 전용 계정을 쓰고 비밀번호는 환경변수로 받는다
_es_client = AsyncElasticsearch(
    hosts=settings.elasticsearch.hosts,
    basic_auth=(settings.elasticsearch.read_only_user, os.environ["MEERKAT_ES_PASSWORD"]),
)
_rule_memory = RuleMemory()


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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
