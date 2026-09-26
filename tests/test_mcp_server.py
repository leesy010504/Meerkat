"""MCP 서버가 임포트되고 도구 목록이 스펙(§6)+추가 도구를 노출하는지 확인한다. ES 연결은 지연되므로 ES 불필요."""

import pytest


@pytest.mark.asyncio
async def test_server_exposes_expected_tools():
    import meerkat.mcp_server.server as server

    names = {tool.name for tool in await server.mcp.list_tools()}
    expected = {
        "es_query_events_tool", "es_aggregate_tool", "rule_syntax_check_tool", "rule_replay_tool",
        "rule_memory_list_tool", "rule_memory_get_tool", "rule_memory_upsert_tool", "create_deploy_pr_tool",
        "rule_deterministic_fix_tool", "rule_logic_check_tool", "role_group_candidates_tool",
        "failure_queue_list_tool", "render_deploy_proposal_tool", "deploy_rule_to_files_tool",
    }
    assert expected <= names, expected - names


@pytest.mark.asyncio
async def test_deterministic_fix_tool_runs_without_external_services():
    import meerkat.mcp_server.server as server

    result = await server.rule_deterministic_fix_tool('drop tcp any any -> any any (msg:"x"; sid:1; rev:1;)')
    assert result.rule_text.startswith("alert ") and "blocking_action" in result.applied_fixes


@pytest.mark.asyncio
async def test_logic_tools_use_repo_role_groups():
    import meerkat.mcp_server.server as server

    rule = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"scan"; flow:to_server; '
        "threshold:type threshold, track by_src, count 70, seconds 60; classtype:attempted-recon; sid:1; rev:1;)"
    )
    assert (await server.rule_logic_check_tool(rule, "scanning")).ok
    assert await server.role_group_candidates_tool(rule) == ["scanning"]
