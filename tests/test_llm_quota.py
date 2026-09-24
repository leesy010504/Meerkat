"""할당량 소진(429 일일 한도) 감지와 키 로테이션 — 실제 API 호출 없이 검증한다."""

import pytest

from meerkat.llm.client import (
    LLMQuotaExhausted,
    _call_with_transient_retry,
    _is_quota_exhausted,
    _retry_after_from_error,
)

GEMINI_429_DAILY = (
    "429 RESOURCE_EXHAUSTED. {'error': {'code': 429, 'message': 'You exceeded your current quota... "
    "Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_requests, "
    "limit: 20, model: gemini-3.6-flash\\nPlease retry in 13h58m24.311053715s.', 'status': 'RESOURCE_EXHAUSTED', "
    "'details': [{'@type': 'type.googleapis.com/google.rpc.QuotaFailure', 'violations': [{'quotaId': "
    "'GenerateRequestsPerDayPerProjectPerModel-FreeTier'}]}, {'@type': 'type.googleapis.com/google.rpc.RetryInfo', "
    "'retryDelay': '50304s'}]}}"
)


class _Err(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def test_retry_delay_is_parsed_from_retryinfo_and_human_text():
    assert _retry_after_from_error(_Err(GEMINI_429_DAILY, 429)) == pytest.approx(50304.3, abs=1)
    assert _retry_after_from_error(_Err("Please retry in 13h58m24.3s.", 429)) == pytest.approx(50304.3)
    assert _retry_after_from_error(_Err("503 UNAVAILABLE overloaded", 503)) is None


def test_daily_quota_429_is_classified_as_exhausted_but_short_429_is_transient():
    assert _is_quota_exhausted(_Err(GEMINI_429_DAILY, 429))
    assert not _is_quota_exhausted(_Err("429 Too Many Requests. retryDelay: '7s'", 429))
    assert not _is_quota_exhausted(_Err("503 UNAVAILABLE", 503))


@pytest.mark.asyncio
async def test_exhausted_quota_raises_immediately_without_backoff(monkeypatch):
    import meerkat.llm.client as client_module

    sleeps: list[float] = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(client_module.asyncio, "sleep", fake_sleep)
    calls = {"n": 0}

    async def failing():
        calls["n"] += 1
        raise _Err(GEMINI_429_DAILY, 429)

    with pytest.raises(LLMQuotaExhausted) as exc_info:
        await _call_with_transient_retry(failing)
    assert calls["n"] == 1 and sleeps == []  # 백오프 없이 1회 호출로 끝
    assert exc_info.value.retry_after_seconds == pytest.approx(50304.3, abs=1)


@pytest.mark.asyncio
async def test_short_transient_429_still_backs_off_and_recovers(monkeypatch):
    import meerkat.llm.client as client_module

    async def fake_sleep(delay):
        pass

    monkeypatch.setattr(client_module.asyncio, "sleep", fake_sleep)
    calls = {"n": 0}

    async def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise _Err("429 Too Many Requests retryDelay: '5s'", 429)
        return "ok"

    assert await _call_with_transient_retry(flaky) == "ok"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_gemini_client_rotates_to_next_key_on_quota_exhaustion(monkeypatch):
    from pydantic import BaseModel

    from meerkat.llm.client import GeminiLLMClient

    class Out(BaseModel):
        x: int

    class FakeModels:
        def __init__(self, key):
            self.key = key

        async def generate_content(self, **kwargs):
            if self.key == "dead":
                raise _Err(GEMINI_429_DAILY, 429)
            return type("R", (), {"parsed": Out(x=7), "text": '{"x": 7}'})()

    class FakeClient:
        def __init__(self, api_key=None, **kwargs):  # http_options 등은 무시
            self.aio = type("Aio", (), {"models": FakeModels(api_key)})()

    import google.genai as genai

    monkeypatch.setattr(genai, "Client", FakeClient)
    client = GeminiLLMClient(api_keys=["dead", "live"])
    result = await client.complete_structured("s", {"a": 1}, Out, model="m")
    assert result.x == 7 and client._active == 1  # 두 번째 키로 넘어감


@pytest.mark.asyncio
async def test_scheduler_stops_cycle_and_does_not_cooldown_offender_on_quota(monkeypatch, tmp_path):
    from conftest import FakeLLMClient

    import meerkat.agent.scheduler as sched
    from meerkat.agent.orchestrator import ModelConfig, VerifyContext
    from meerkat.agent.scheduler import SchedulerConfig, SchedulerState, poll_once
    from meerkat.ingestion.baseline import BaselineStats
    from meerkat.mcp_server.tools.es_aggregate import AggregateResult, Offender
    from meerkat.storage.failure_queue import FailureQueue
    from meerkat.storage.rule_memory import RuleMemory

    async def fake_aggregate(client, metric, start, end, window_seconds, top_n=20, compare_baseline=True, threshold_margin=1.0):
        return AggregateResult(metric=metric, window_seconds=window_seconds,
                               top_offenders=[Offender(src_ip="10.0.0.1", value=99), Offender(src_ip="10.0.0.2", value=98)],
                               baseline=BaselineStats(p50=1, p95=2, p99=3, mean=1, std=0), suggested_threshold=3)

    async def fake_query(client, index, start, end, src_ip=None, **kwargs):
        return [{"_id": f"e-{src_ip}", "src_ip": src_ip}]

    seen: list[str] = []

    async def fake_orchestrate(**kwargs):
        seen.append(kwargs["flow_summary"]["src_ip"])
        raise LLMQuotaExhausted("daily quota", 50000)

    monkeypatch.setattr(sched, "es_aggregate", fake_aggregate)
    monkeypatch.setattr(sched, "es_query_events", fake_query)
    monkeypatch.setattr(sched, "orchestrate", fake_orchestrate)

    state = SchedulerState()
    config = SchedulerConfig(metrics=("unique_dst_ports_per_src",), audit_log_path=str(tmp_path / "a.jsonl"))
    models = ModelConfig(relation_assess="f", rule_generate="f", rule_repair="f", rule_select="f")
    with pytest.raises(LLMQuotaExhausted):
        await poll_once(None, FakeLLMClient(), RuleMemory(path=tmp_path / "m.json"), models,
                        VerifyContext(attack_pcaps=[], benign_pcaps=[]), FailureQueue(path=tmp_path / "q.json"),
                        config, state=state)
    assert seen == ["10.0.0.1"]  # 첫 offender에서 멈춤 — 나머지 호출을 태우지 않는다
    assert state.handled_offenders == {}  # 쿨다운에 넣지 않음 → 할당량 복구 후 다시 처리됨
    records = (tmp_path / "a.jsonl").read_text().splitlines()
    assert len(records) == 1 and '"outcome": "llm_quota_exhausted"' in records[0]


def test_gemini_keys_from_env_collects_all_named_keys_without_duplicates():
    from meerkat.llm.client import gemini_keys_from_env

    env = {"GEMINI_API_KEY": "a", "GEMINI_API_KEY_DENIED": "b", "GEMINI_API_KEY_EXHAUSTED": "c",
           "GEMINI_API_KEY_DENIED2": "a", "OTHER": "z", "GEMINI_API_KEY_EMPTY": ""}
    keys, labels = gemini_keys_from_env(env)
    assert keys == ["a", "b", "c"]  # 기본 키가 먼저, 중복 값(DENIED2=a)·빈 값 제외
    assert labels == ["GEMINI_API_KEY", "GEMINI_API_KEY_DENIED", "GEMINI_API_KEY_EXHAUSTED"]
    keys, labels = gemini_keys_from_env({**env, "GEMINI_API_KEYS": "x, y"})
    assert keys == ["x", "y"] and labels == ["GEMINI_API_KEYS[0]", "GEMINI_API_KEYS[1]"]


@pytest.mark.asyncio
async def test_rejected_key_is_skipped_permanently_and_its_value_never_logged(monkeypatch, caplog):
    import logging

    from pydantic import BaseModel

    from meerkat.llm.client import GeminiLLMClient

    class Out(BaseModel):
        x: int

    calls: list[str] = []

    class FakeModels:
        def __init__(self, key):
            self.key = key

        async def generate_content(self, **kwargs):
            calls.append(self.key)
            if self.key == "SECRET-denied":
                raise _Err("403 PERMISSION_DENIED. API key SECRET-denied not valid", 403)
            if self.key == "SECRET-dry":
                raise _Err(GEMINI_429_DAILY, 429)
            return type("R", (), {"parsed": Out(x=1), "text": '{"x": 1}'})()

    class FakeClient:
        def __init__(self, api_key=None, **kwargs):
            self.aio = type("Aio", (), {"models": FakeModels(api_key)})()

    import google.genai as genai

    monkeypatch.setattr(genai, "Client", FakeClient)
    client = GeminiLLMClient(api_keys=["SECRET-denied", "SECRET-dry", "SECRET-live"],
                             key_labels=["K_DENIED", "K_DRY", "K_LIVE"])
    with caplog.at_level(logging.WARNING):
        assert (await client.complete_structured("s", {}, Out, model="m")).x == 1
        assert (await client.complete_structured("s", {}, Out, model="m")).x == 1
    assert calls == ["SECRET-denied", "SECRET-dry", "SECRET-live", "SECRET-live"]  # 두 번째 호출은 살아있는 키로 바로
    assert "SECRET" not in caplog.text and "K_DENIED" in caplog.text


@pytest.mark.asyncio
async def test_all_keys_rejected_raises_key_rejected(monkeypatch):
    from pydantic import BaseModel

    from meerkat.llm.client import GeminiLLMClient, LLMKeyRejected

    class Out(BaseModel):
        x: int

    class FakeModels:
        async def generate_content(self, **kwargs):
            raise _Err("400 API_KEY_INVALID", 400)

    class FakeClient:
        def __init__(self, api_key=None, **kwargs):
            self.aio = type("Aio", (), {"models": FakeModels()})()

    import google.genai as genai

    monkeypatch.setattr(genai, "Client", FakeClient)
    client = GeminiLLMClient(api_keys=["a", "b"])
    with pytest.raises(LLMKeyRejected) as exc_info:
        await client.complete_structured("s", {}, Out, model="m")
    assert "a" not in str(exc_info.value).split()  # 메시지에 키 값이 없다


@pytest.mark.asyncio
async def test_key_state_is_shared_across_new_clients(monkeypatch):
    """두 번째 클라이언트는 거부된 키·소진된 키를 다시 두드리지 않고 살아있는 키로 바로 간다."""
    from pydantic import BaseModel

    from meerkat.llm.client import GeminiLLMClient, LLMQuotaExhausted

    class Out(BaseModel):
        x: int

    calls: list[str] = []

    class FakeModels:
        def __init__(self, key):
            self.key = key

        async def generate_content(self, **kwargs):
            calls.append(self.key)
            if self.key == "denied":
                raise _Err("403 PERMISSION_DENIED", 403)
            if self.key == "dry":
                raise _Err(GEMINI_429_DAILY, 429)
            return type("R", (), {"parsed": Out(x=1), "text": '{"x": 1}'})()

    class FakeClient:
        def __init__(self, api_key=None, **kwargs):
            self.aio = type("Aio", (), {"models": FakeModels(api_key)})()

    import google.genai as genai

    monkeypatch.setattr(genai, "Client", FakeClient)
    await GeminiLLMClient(api_keys=["dry", "denied", "live"]).complete_structured("s", {}, Out, model="m")
    assert calls == ["dry", "denied", "live"]
    calls.clear()
    await GeminiLLMClient(api_keys=["dry", "denied", "live"]).complete_structured("s", {}, Out, model="m")
    assert calls == ["live"]  # 새 클라이언트도 바로 살아있는 키로

    calls.clear()
    with pytest.raises(LLMQuotaExhausted):  # 살아있는 키가 없으면 호출 없이 한도 소진으로 끝난다
        await GeminiLLMClient(api_keys=["dry", "denied"]).complete_structured("s", {}, Out, model="m")
    assert calls == []
