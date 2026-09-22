"""LLM 없이 동작하는 결정적 템플릿 클라이언트 (`llm.provider: template`).

용도:
  - API 키/할당량이 없는 환경(CI, 오프라인 데모)에서 파이프라인 전체를 끝까지 돌려보기
  - 평가(ablation)에서 "LLM 대신 템플릿"이라는 하한 기준선
  - 무료 티어 일일 한도가 소진됐을 때의 폴백

LLMClient 프로토콜(complete_structured)을 그대로 구현하고 output_schema별로 결정적 응답을 만든다.
관계 판단은 항상 "신규", 룰 생성은 트리거 지표(flow_summary.metric)에 맞는 rate 기반 템플릿에
suggested_threshold를 그대로 박는다. 수리는 진단 접두사에 따라 결정적으로 한 가지씩만 손본다 —
실제 LLM처럼 창의적으로 고치지는 못하므로 검증 루프가 실패하면 그대로 실패로 끝난다.
"""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from meerkat.agent.schemas import (
    CategoryProposalOutput,
    RelationAssessOutput,
    RuleGenerateOutput,
    RuleRepairOutput,
    RuleSelectOutput,
)

T = TypeVar("T", bound=BaseModel)

# metric → (헤더 프로토콜/포트, 옵션 접두, classtype, msg)
_METRIC_TEMPLATES: dict[str, tuple[str, str, str, str]] = {
    "unique_dst_ports_per_src": ("tcp $EXTERNAL_NET any -> $HOME_NET any", "flow:to_server; flags:S,12;",
                                 "attempted-recon", "LOCAL Port Scan - Multiple Ports from Single Source"),
    "conn_count_per_src_port": ("tcp $EXTERNAL_NET any -> $HOME_NET any", "flow:to_server; flags:S,12;",
                                "attempted-recon", "LOCAL Connection Flood from Single Source"),
    "failed_conn_ratio_per_src": ("tcp $EXTERNAL_NET any -> $HOME_NET any", "flow:to_server; flags:S,12;",
                                  "attempted-recon", "LOCAL Many Failed Connections from Single Source"),
    "unique_endpoints_per_src": ("http $EXTERNAL_NET any -> $HOME_NET any", "flow:to_server; http.method; content:\"GET\";",
                                 "web-application-attack", "LOCAL Directory Enumeration from Single Source"),
    "http_4xx_ratio_per_src": ("http $EXTERNAL_NET any -> $HOME_NET any", "flow:to_server; http.method; content:\"GET\";",
                               "web-application-attack", "LOCAL Repeated 4xx Requests from Single Source"),
    "request_rate_per_src": ("http $EXTERNAL_NET any -> $HOME_NET any", "flow:to_server;",
                             "web-application-attack", "LOCAL HTTP Request Flood from Single Source"),
    "dns_query_rate_per_src": ("udp $EXTERNAL_NET any -> $HOME_NET 53", "", "denial-of-service",
                               "LOCAL DNS Query Flood from Single Source"),
}


class TemplateLLMClient:
    """LLMClient 프로토콜을 만족하는 결정적 구현. 호출 횟수를 calls에 기록한다."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def complete_structured(
        self,
        system_prompt: str,
        user_content: dict,
        output_schema: type[T],
        model: str,
        temperature: float = 0.0,
    ) -> T:
        self.calls.append(output_schema.__name__)
        if output_schema is RelationAssessOutput:
            return RelationAssessOutput(is_variant=False, matched_sid=None,
                                        reasoning="template provider: 관계 판단 없이 항상 신규 유형으로 처리")  # type: ignore[return-value]
        if output_schema is RuleGenerateOutput:
            return self._generate(user_content)  # type: ignore[return-value]
        if output_schema is RuleRepairOutput:
            return RuleRepairOutput(repaired_rule_text=self._repair(user_content))  # type: ignore[return-value]
        if output_schema is RuleSelectOutput:
            return RuleSelectOutput(selected_index=0, reason="template provider: 첫 후보")  # type: ignore[return-value]
        if output_schema is CategoryProposalOutput:
            flow = user_content.get("flow_summary") or {}
            return CategoryProposalOutput(  # type: ignore[return-value]
                candidate_category_name=f"unclassified-{str(flow.get('metric', 'traffic')).replace('_', '-')}",
                protocols=["tcp"], classtypes=["misc-activity"], direction="inbound",
                expected_keywords=["threshold"],
                reasoning="template provider: 자동 분류 불가, 사람 검토 필요",
            )
        raise ValueError(f"template provider has no response for {output_schema.__name__}")

    # ---- 생성 --------------------------------------------------------------------------

    def _generate(self, user_content: dict) -> RuleGenerateOutput:
        flow = user_content.get("flow_summary") or {}
        metric = flow.get("metric", "unique_dst_ports_per_src")
        header, prefix, classtype, msg = _METRIC_TEMPLATES.get(metric, _METRIC_TEMPLATES["unique_dst_ports_per_src"])
        sids = user_content.get("available_sids") or [1000000]
        threshold = user_content.get("suggested_threshold") or {}
        count = int(threshold.get("count") or 50)
        seconds = int(threshold.get("seconds") or 60)
        # 샘플 이벤트가 전부 같은 목적지 포트를 때리면(브루트포스/연결 폭주) 그 포트로 좁힌다 —
        # any 포트의 연결 수 룰은 정상 브라우징에서도 걸리지만 단일 서비스 포트로 좁히면 안 걸린다.
        dest_port = _common_dest_port(flow.get("sample_events") or [])
        if dest_port is not None and header.endswith("$HOME_NET any") and metric != "unique_dst_ports_per_src":
            header = header[: -len("any")] + str(dest_port)
        rule = (
            f'alert {header} (msg:"{msg}"; {prefix} '
            f"threshold:type threshold, track by_src, count {count}, seconds {seconds}; "
            f"classtype:{classtype}; sid:{sids[0]}; rev:1;)"
        ).replace("( ", "(").replace("  ", " ")
        candidates = []
        # 웹 지표인데 샘플 이벤트가 전부 같은 비브라우저 UA(스캐너 도구)를 쓰면 그 UA를 잡는 후보를 앞에 둔다
        tool_ua = _common_tool_user_agent(flow.get("sample_events") or [])
        if tool_ua and header.startswith("http"):
            candidates.append(
                f'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Scanner User-Agent {tool_ua}"; '
                f'flow:to_server; http.user_agent; content:"{tool_ua}"; nocase; '
                f"classtype:{classtype}; sid:{sids[0]}; rev:1;)"
            )
        candidates.append(rule)
        return RuleGenerateOutput(
            candidates=candidates,
            attack_summary=f"template provider: {metric} 지표가 baseline 임계값({count}/{seconds}s)을 초과한 출발지에 대한 rate 기반 룰",
        )

    # ---- 수리 (결정적, 한 번에 하나) ------------------------------------------------------------

    @staticmethod
    def _repair(user_content: dict) -> str:
        rule = user_content.get("rule_text", "")
        diagnostic = str(user_content.get("diagnostic", ""))
        target_flow = user_content.get("target_flow") or user_content.get("malicious_flow") or {}
        dest_port = _common_dest_port(target_flow.get("sample_events") or []) if isinstance(target_flow, dict) else None
        if diagnostic.startswith("false_positive") and dest_port is not None and "-> $HOME_NET any" in rule:
            # 정상 트래픽에 걸렸고 공격 샘플이 한 포트만 때린다면 그 포트로 좁히는 게 첫 수다
            return rule.replace("-> $HOME_NET any", f"-> $HOME_NET {dest_port}", 1)
        if diagnostic.startswith("false_positive") and "flags:S,12;" not in rule and rule.startswith("alert tcp"):
            # 모든 패킷을 세고 있었다면 SYN만 세게 좁힌다
            return rule.replace("flow:to_server;", "flow:to_server; flags:S,12;", 1)
        if diagnostic.startswith("false_positive") and "count " in rule:
            # 임계값을 두 배로 올린다 (baseline 값 그대로가 정상 트래픽에 걸렸다는 뜻)
            import re

            return re.sub(r"count (\d+)", lambda m: f"count {int(m.group(1)) * 2}", rule, count=1)
        if diagnostic.startswith("role_group") and "any any -> any any" in rule:
            return rule.replace("any any -> any any", "$EXTERNAL_NET any -> $HOME_NET any")
        return rule  # 더 할 수 있는 게 없다 — 검증 루프가 그대로 실패시킨다


_BROWSER_MARKERS = ("mozilla", "applewebkit", "chrome", "safari", "firefox", "edge", "opera")


def _common_tool_user_agent(sample_events: list[dict]) -> str | None:
    """샘플 이벤트들이 공유하는 비브라우저 UA의 제품 토큰(예: "gobuster")을 돌려준다. 없으면 None."""
    uas: set[str] = set()
    for event in sample_events:
        for container in (event.get("nginx"), event.get("http")):
            if isinstance(container, dict):
                ua = container.get("user_agent") or container.get("http_user_agent")
                if ua:
                    uas.add(str(ua))
    if len(uas) != 1:
        return None
    ua = next(iter(uas))
    if any(marker in ua.lower() for marker in _BROWSER_MARKERS):
        return None
    product = ua.split("/", 1)[0].split(" ", 1)[0].strip()
    # content에 안전하게 들어갈 수 있는 토큰만 (영숫자, -, _, .)
    if not product or not all(ch.isalnum() or ch in "-_." for ch in product):
        return None
    return product


def _common_dest_port(sample_events: list[dict]) -> int | None:
    ports = {event.get("dest_port") for event in sample_events if event.get("dest_port") is not None}
    if len(ports) == 1:
        return int(next(iter(ports)))
    return None
