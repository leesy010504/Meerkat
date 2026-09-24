"""ES 없이 es_aggregate/es_query_events를 스텁으로 바꿔 스케줄러의 offender 쿨다운을 검증한다."""

import pytest
from conftest import FakeLLMClient

import meerkat.agent.scheduler as sched
from meerkat.agent.orchestrator import AlreadyCovered, ModelConfig, VerifyContext
from meerkat.agent.scheduler import SchedulerConfig, SchedulerState, poll_once
from meerkat.ingestion.baseline import BaselineStats
from meerkat.mcp_server.tools.es_aggregate import AggregateResult, Offender
from meerkat.storage.failure_queue import FailureQueue
from meerkat.storage.rule_memory import RuleMemory

MODELS = ModelConfig(relation_assess="fake", rule_generate="fake", rule_repair="fake", rule_select="fake")


def _stub_es(monkeypatch, offenders: list[Offender]):
    async def fake_aggregate(client, metric, start, end, window_seconds, top_n=20, compare_baseline=True, threshold_margin=1.0):
        return AggregateResult(
            metric=metric, window_seconds=window_seconds, top_offenders=offenders,
            baseline=BaselineStats(p50=2, p95=5, p99=8, mean=2.5, std=1.0), suggested_threshold=8,
        )

    async def fake_query(client, index, start, end, src_ip=None, **kwargs):
        return [{"_id": f"evt-{src_ip}", "src_ip": src_ip, "dest_ip": "10.0.0.1", "proto": "TCP"}]

    monkeypatch.setattr(sched, "es_aggregate", fake_aggregate)
    monkeypatch.setattr(sched, "es_query_events", fake_query)


@pytest.mark.asyncio
async def test_same_offender_is_not_reprocessed_within_cooldown(monkeypatch, tmp_path):
    _stub_es(monkeypatch, [Offender(src_ip="10.0.0.99", value=80)])

    calls: list[str] = []

    async def fake_orchestrate(**kwargs):
        calls.append(kwargs["flow_summary"]["src_ip"])
        raise AlreadyCovered(1000001)

    monkeypatch.setattr(sched, "orchestrate", fake_orchestrate)

    state = SchedulerState()
    config = SchedulerConfig(metrics=("unique_dst_ports_per_src",), offender_cooldown_seconds=3600)
    args = (None, FakeLLMClient(), RuleMemory(path=tmp_path / "m.json"), MODELS,
            VerifyContext(attack_pcaps=[], benign_pcaps=[]), FailureQueue(path=tmp_path / "q.json"), config)

    await poll_once(*args, state=state)
    await poll_once(*args, state=state)
    await poll_once(*args, state=state)

    assert calls == ["10.0.0.99"]  # 두 번째/세 번째 주기에서는 다시 올리지 않는다


@pytest.mark.asyncio
async def test_cooldown_expires_and_offender_is_reprocessed(monkeypatch, tmp_path):
    _stub_es(monkeypatch, [Offender(src_ip="10.0.0.99", value=80)])

    calls: list[str] = []

    async def fake_orchestrate(**kwargs):
        calls.append(kwargs["flow_summary"]["src_ip"])
        raise AlreadyCovered(1000001)

    monkeypatch.setattr(sched, "orchestrate", fake_orchestrate)

    state = SchedulerState()
    config = SchedulerConfig(metrics=("unique_dst_ports_per_src",), offender_cooldown_seconds=10)
    args = (None, FakeLLMClient(), RuleMemory(path=tmp_path / "m.json"), MODELS,
            VerifyContext(attack_pcaps=[], benign_pcaps=[]), FailureQueue(path=tmp_path / "q.json"), config)

    await poll_once(*args, state=state)
    # 쿨다운이 지난 것처럼 처리 시각을 과거로 돌린다
    key = ("unique_dst_ports_per_src", "10.0.0.99")
    state.handled_offenders[key] -= 11
    await poll_once(*args, state=state)

    assert calls == ["10.0.0.99", "10.0.0.99"]


@pytest.mark.asyncio
async def test_without_shared_state_every_poll_is_independent(monkeypatch, tmp_path):
    """state를 안 넘기면(기존 호출 방식) 쿨다운이 걸리지 않아야 한다 — 하위 호환."""
    _stub_es(monkeypatch, [Offender(src_ip="10.0.0.99", value=80)])

    calls: list[str] = []

    async def fake_orchestrate(**kwargs):
        calls.append(kwargs["flow_summary"]["src_ip"])
        raise AlreadyCovered(1000001)

    monkeypatch.setattr(sched, "orchestrate", fake_orchestrate)

    config = SchedulerConfig(metrics=("unique_dst_ports_per_src",))
    args = (None, FakeLLMClient(), RuleMemory(path=tmp_path / "m.json"), MODELS,
            VerifyContext(attack_pcaps=[], benign_pcaps=[]), FailureQueue(path=tmp_path / "q.json"), config)

    await poll_once(*args)
    await poll_once(*args)
    assert calls == ["10.0.0.99", "10.0.0.99"]


@pytest.mark.asyncio
async def test_verified_rule_is_written_to_rules_dir_in_file_mode(monkeypatch, tmp_path):
    import datetime

    from meerkat.storage.rule_memory import RuleItem

    _stub_es(monkeypatch, [Offender(src_ip="10.0.0.99", value=80)])
    now = datetime.datetime.now(datetime.timezone.utc)
    item = RuleItem(
        sid=1000000, rev=1, role_group="scanning", repr_event_ids=["evt-10.0.0.99"], repr_pcap_path=None,
        created_at=now, updated_at=now, origin="generated", rationale="관계 판단: 신규 유형 — 스캔",
        rule_text='alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"scan"; sid:1000000; rev:1;)',
    )

    async def fake_orchestrate(**kwargs):
        return item

    monkeypatch.setattr(sched, "orchestrate", fake_orchestrate)

    config = SchedulerConfig(
        metrics=("unique_dst_ports_per_src",), deploy_mode="file",
        rules_dir=str(tmp_path / "rules"), proposals_dir=str(tmp_path / "proposals"),
    )
    deployed = await poll_once(
        None, FakeLLMClient(), RuleMemory(path=tmp_path / "m.json"), MODELS,
        VerifyContext(attack_pcaps=[], benign_pcaps=[]), FailureQueue(path=tmp_path / "q.json"), config,
    )

    assert deployed == [item]
    assert "sid:1000000;" in (tmp_path / "rules" / "scanning.rules").read_text()
    proposals = list((tmp_path / "proposals").glob("*-sid1000000-rev1.md"))
    assert len(proposals) == 1 and "10.0.0.99" in proposals[0].read_text()


@pytest.mark.asyncio
async def test_deploy_mode_none_leaves_rules_dir_untouched(monkeypatch, tmp_path):
    import datetime

    from meerkat.storage.rule_memory import RuleItem

    _stub_es(monkeypatch, [Offender(src_ip="10.0.0.99", value=80)])
    now = datetime.datetime.now(datetime.timezone.utc)
    item = RuleItem(
        sid=1000000, rev=1, role_group="scanning", repr_event_ids=[], repr_pcap_path=None,
        created_at=now, updated_at=now, origin="generated",
        rule_text='alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"scan"; sid:1000000; rev:1;)',
    )

    async def fake_orchestrate(**kwargs):
        return item

    monkeypatch.setattr(sched, "orchestrate", fake_orchestrate)
    config = SchedulerConfig(metrics=("unique_dst_ports_per_src",), deploy_mode="none", rules_dir=str(tmp_path / "rules"))
    await poll_once(
        None, FakeLLMClient(), RuleMemory(path=tmp_path / "m.json"), MODELS,
        VerifyContext(attack_pcaps=[], benign_pcaps=[]), FailureQueue(path=tmp_path / "q.json"), config,
    )
    assert not (tmp_path / "rules").exists()


@pytest.mark.asyncio
async def test_rule_count_comes_from_packet_basis_metric_not_cardinality(monkeypatch, tmp_path):
    """unique_dst_ports_per_src(고유 포트 수)로 트리거돼도 룰의 count는 conn_count_per_src_port
    (연결 수) baseline × margin에서 나와야 한다 — 고유 포트 p99=4를 count 4로 쓰면 브라우저 하나도 걸린다."""
    seen_metrics: list[str] = []

    async def fake_aggregate(client, metric, start, end, window_seconds, top_n=20, compare_baseline=True,
                             threshold_margin=1.0):
        seen_metrics.append(metric)
        if metric == "unique_dst_ports_per_src":
            return AggregateResult(metric=metric, window_seconds=window_seconds,
                                   top_offenders=[Offender(src_ip="10.0.0.99", value=80)],
                                   baseline=BaselineStats(p50=2, p95=3, p99=4, mean=2, std=1), suggested_threshold=4)
        # 기준 지표: 평시 연결 수 p99=40 → ×1.5 = 60
        import math

        return AggregateResult(metric=metric, window_seconds=window_seconds, top_offenders=[],
                               baseline=BaselineStats(p50=10, p95=30, p99=40, mean=12, std=8),
                               suggested_threshold=math.ceil(40 * threshold_margin))

    async def fake_query(client, index, start, end, src_ip=None, **kwargs):
        return [{"_id": "e1", "src_ip": src_ip}]

    captured: dict = {}

    async def fake_orchestrate(**kwargs):
        captured.update(kwargs["suggested_threshold"])
        raise AlreadyCovered(1)

    monkeypatch.setattr(sched, "es_aggregate", fake_aggregate)
    monkeypatch.setattr(sched, "es_query_events", fake_query)
    monkeypatch.setattr(sched, "orchestrate", fake_orchestrate)

    config = SchedulerConfig(metrics=("unique_dst_ports_per_src",), threshold_margin=1.5, min_rule_count=5)
    await poll_once(None, FakeLLMClient(), RuleMemory(path=tmp_path / "m.json"), MODELS,
                    VerifyContext(attack_pcaps=[], benign_pcaps=[]), FailureQueue(path=tmp_path / "q.json"), config)

    assert captured["count"] == 60 and captured["seconds"] == 300
    assert captured["basis_metric"] == "conn_count_per_src_port"
    assert captured["anomaly_metric"] == "unique_dst_ports_per_src" and captured["anomaly_threshold"] == 4
    assert seen_metrics == ["unique_dst_ports_per_src", "conn_count_per_src_port"]


@pytest.mark.asyncio
async def test_min_rule_count_floor_applies(monkeypatch, tmp_path):
    async def fake_aggregate(client, metric, start, end, window_seconds, top_n=20, compare_baseline=True,
                             threshold_margin=1.0):
        return AggregateResult(metric=metric, window_seconds=window_seconds,
                               top_offenders=[Offender(src_ip="10.0.0.99", value=80)],
                               baseline=BaselineStats(p50=1, p95=1, p99=1, mean=1, std=0), suggested_threshold=2)

    async def fake_query(client, index, start, end, src_ip=None, **kwargs):
        return [{"_id": "e1", "src_ip": src_ip}]

    captured: dict = {}

    async def fake_orchestrate(**kwargs):
        captured.update(kwargs["suggested_threshold"])
        raise AlreadyCovered(1)

    monkeypatch.setattr(sched, "es_aggregate", fake_aggregate)
    monkeypatch.setattr(sched, "es_query_events", fake_query)
    monkeypatch.setattr(sched, "orchestrate", fake_orchestrate)

    config = SchedulerConfig(metrics=("conn_count_per_src_port",), threshold_margin=1.5, min_rule_count=5)
    await poll_once(None, FakeLLMClient(), RuleMemory(path=tmp_path / "m.json"), MODELS,
                    VerifyContext(attack_pcaps=[], benign_pcaps=[]), FailureQueue(path=tmp_path / "q.json"), config)
    assert captured["count"] == 5  # ceil(1*1.5)=2 → 하한 5
