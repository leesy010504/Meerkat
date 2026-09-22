import asyncio
import json
import logging
import os
import re
from typing import Protocol, TypeVar

from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# 503 "high demand"는 수십 초 지속되는 경우가 흔해서(실측) 총 1분 남짓 기다린다
_TRANSIENT_BACKOFF_SECONDS = [2, 5, 10, 20, 30]
# 서버가 알려준 재시도 대기가 이보다 길면 "일시적"이 아니라 할당량 소진으로 본다 (무료 티어 일일 한도 등)
_MAX_TRANSIENT_RETRY_DELAY_SECONDS = 120


class LLMQuotaExhausted(Exception):
    """일일/프로젝트 할당량 소진. 짧은 백오프로 해결되지 않으니 호출자가 긴 시간 멈춰야 한다."""

    def __init__(self, message: str, retry_after_seconds: float | None = None):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(message)


class LLMKeyRejected(Exception):
    """키 자체가 거부됨(401/403, 잘못된 키, 권한 없음, 결제 계정 비활성 등). 재시도해도 소용없다."""


def _is_key_rejected(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    text = str(exc)
    if status in (401, 403):
        return True
    return any(marker in text for marker in (
        "API_KEY_INVALID", "API key not valid", "PERMISSION_DENIED", "API key expired",
        "CONSUMER_SUSPENDED", "SERVICE_DISABLED",
    ))


_RETRY_DELAY_RE = re.compile(r"retry(?:Delay|\s+in)['\"]?\s*[:=]?\s*'?(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?", re.I)


def _retry_after_from_error(exc: Exception) -> float | None:
    """SDK 에러 문자열에서 RetryInfo.retryDelay('50304s') 또는 'retry in 13h58m24s'를 읽는다."""
    text = str(exc)
    best: float | None = None
    for match in _RETRY_DELAY_RE.finditer(text):
        h, m, sec = match.groups()
        if not any((h, m, sec)):
            continue
        total = float(h or 0) * 3600 + float(m or 0) * 60 + float(sec or 0)
        best = max(best or 0, total)
    return best


def _is_quota_exhausted(exc: Exception, status=None) -> bool:
    if status is None:
        status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    text = str(exc)
    if status != 429 and "RESOURCE_EXHAUSTED" not in text:
        return False
    retry_after = _retry_after_from_error(exc)
    return (retry_after is not None and retry_after > _MAX_TRANSIENT_RETRY_DELAY_SECONDS) or (
        "quota" in text.lower() and "per day" in text.lower()
    ) or "PerDay" in text


async def _call_with_transient_retry(fn):
    """429/5xx 등 일시적 서버 에러를 백오프하며 재시도한다.

    단, 일일 할당량 소진(RetryInfo가 수 시간 뒤를 가리키는 429)은 재시도해도 소용없으니
    LLMQuotaExhausted로 바로 올린다 — 그래야 스케줄러가 같은 주기에 남은 호출을 다 태우지 않는다.
    """
    last_exc: Exception | None = None
    for delay in [*_TRANSIENT_BACKOFF_SECONDS, None]:
        try:
            return await fn()
        except (LLMQuotaExhausted, LLMKeyRejected):
            raise
        except Exception as exc:  # noqa: BLE001 - 어떤 SDK든 동일하게 처리
            status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
            if _is_key_rejected(exc):
                # 키 값이 메시지에 섞여 나오는 SDK가 있어 원문을 싣지 않는다
                raise LLMKeyRejected(f"key rejected (status={status})") from None
            if _is_quota_exhausted(exc, status):
                raise LLMQuotaExhausted(str(exc)[:500], _retry_after_from_error(exc)) from exc
            is_transient = status in (429, 500, 502, 503, 504) or "UNAVAILABLE" in str(exc)
            if not is_transient or delay is None:
                raise
            last_exc = exc
            await asyncio.sleep(delay)
    raise last_exc  # pragma: no cover - 위 루프가 항상 raise/return 함


class SchemaViolationError(Exception):
    pass


class LLMClient(Protocol):
    """LLM 호출 추상화. 구현체를 교체해도 호출부는 변하지 않는다."""

    async def complete_structured(
        self,
        system_prompt: str,
        user_content: dict,
        output_schema: type[T],
        model: str,
        temperature: float = 0.0,
    ) -> T: ...


class AnthropicLLMClient:
    def __init__(self, api_key: str | None = None, max_retries: int = 2):
        from anthropic import AsyncAnthropic

        self._client = AsyncAnthropic(api_key=api_key)
        self._max_retries = max_retries

    async def complete_structured(
        self,
        system_prompt: str,
        user_content: dict,
        output_schema: type[T],
        model: str,
        temperature: float = 0.0,
    ) -> T:
        # user_content는 JSON으로 직렬화해 전달한다
        last_error: str | None = None

        for _ in range(self._max_retries + 1):
            response = await _call_with_transient_retry(
                lambda: self._client.messages.create(
                    model=model,
                    system=system_prompt,
                    max_tokens=4096,
                    messages=[{"role": "user", "content": json.dumps(user_content, ensure_ascii=False)}],
                    tools=[
                        {
                            "name": "emit_result",
                            "description": "구조화된 결과를 반환한다.",
                            "input_schema": output_schema.model_json_schema(),
                        }
                    ],
                    tool_choice={"type": "tool", "name": "emit_result"},
                )
            )

            tool_use = next((b for b in response.content if b.type == "tool_use"), None)
            if tool_use is None:
                last_error = "no tool_use block in response"
                continue

            try:
                return output_schema.model_validate(tool_use.input)
            except Exception as exc:  # noqa: BLE001 - 스키마 검증 실패는 재시도 대상
                last_error = str(exc)
                continue

        raise SchemaViolationError(
            f"LLM output did not match {output_schema.__name__} "
            f"after {self._max_retries + 1} attempts: {last_error}"
        )


# 프로세스 전체에서 공유하는 키 상태. ablation/데모는 시나리오마다 클라이언트를 새로 만드는데, 상태가
# 클라이언트마다 따로면 매번 거부된 키·소진된 키를 다시 두드린다 (429 요청도 한도를 깎는다).
# 키 값 대신 해시를 키로 써서 메모리에 원문을 더 남기지 않는다.
import hashlib as _hashlib  # noqa: E402
import time as _time  # noqa: E402

_REJECTED_KEYS: set[str] = set()
_EXHAUSTED_UNTIL: dict[str, float] = {}


def _key_id(key: str | None) -> str:
    return _hashlib.sha256((key or "").encode()).hexdigest()[:16]


def reset_key_state() -> None:
    _REJECTED_KEYS.clear()
    _EXHAUSTED_UNTIL.clear()


class GeminiLLMClient:
    """api_keys를 여러 개 주면 일일 할당량이 소진된 키를 건너뛰고 다음 키로 넘어간다
    (무료 티어는 프로젝트별 일일 한도가 작다). 전부 소진되면 LLMQuotaExhausted."""

    def __init__(self, api_key: str | None = None, max_retries: int = 2, api_keys: list[str] | None = None,
                 key_labels: list[str] | None = None):
        from google import genai

        keys = [k for k in (api_keys or ([api_key] if api_key else [None])) if k is not None or not api_keys]
        # SDK 자체 재시도(tenacity)를 끈다 — 우리 백오프(_call_with_transient_retry)와 겹치면 503 한 번에
        # 요청이 수십 번 나가고, 실패한 요청도 무료 티어 일일 한도를 깎는다 (실측: 503 몇 번에 20회 소진).
        http_options = genai.types.HttpOptions(retry_options=genai.types.HttpRetryOptions(attempts=1))
        self._clients = [genai.Client(api_key=k, http_options=http_options) for k in keys]
        self._ids = [_key_id(k) for k in keys]
        # 로그에는 키 값이 아니라 라벨(환경변수 이름 등)만 남긴다
        self._labels = key_labels if key_labels and len(key_labels) == len(keys) else [f"#{i}" for i in range(len(keys))]
        self._active = 0
        self._max_retries = max_retries
        self._advance_to_usable()

    def _usable(self, index: int) -> bool:
        key_id = self._ids[index]
        return key_id not in _REJECTED_KEYS and _EXHAUSTED_UNTIL.get(key_id, 0) <= _time.time()

    def _advance_to_usable(self) -> None:
        for offset in range(len(self._clients)):
            index = (self._active + offset) % len(self._clients)
            if self._usable(index):
                self._active = index
                return

    @property
    def active_key_label(self) -> str:
        return self._labels[self._active]

    @property
    def _client(self):
        return self._clients[self._active]

    async def _generate(self, **kwargs):
        """현재 키로 호출하고, 할당량 소진이나 키 거부면 다음 키로 넘어가 다시 시도한다.

        전부 막히면: 한도 소진이 하나라도 있었으면 LLMQuotaExhausted(스케줄러가 쉬었다 재시도),
        전부 거부였으면 LLMKeyRejected.
        """
        quota_error: LLMQuotaExhausted | None = None
        for _ in range(len(self._clients)):
            if not self._usable(self._active):
                self._active = (self._active + 1) % len(self._clients)
                continue
            try:
                return await _call_with_transient_retry(
                    lambda: self._client.aio.models.generate_content(**kwargs)
                )
            except LLMQuotaExhausted as exc:
                quota_error = quota_error or exc
                _EXHAUSTED_UNTIL[self._ids[self._active]] = _time.time() + (exc.retry_after_seconds or 3600)
                logger.warning("gemini key %s quota exhausted, trying next key", self.active_key_label)
            except LLMKeyRejected:
                _REJECTED_KEYS.add(self._ids[self._active])
                logger.warning("gemini key %s rejected, skipping it from now on", self.active_key_label)
            self._active = (self._active + 1) % len(self._clients)
        if quota_error is not None:
            raise quota_error
        if any(_EXHAUSTED_UNTIL.get(i, 0) > _time.time() for i in self._ids):
            raise LLMQuotaExhausted("all usable gemini keys are quota-exhausted in this process",
                                    max(_EXHAUSTED_UNTIL.get(i, 0) for i in self._ids) - _time.time())
        raise LLMKeyRejected("all gemini keys rejected")

    async def complete_structured(
        self,
        system_prompt: str,
        user_content: dict,
        output_schema: type[T],
        model: str,
        temperature: float = 0.0,
    ) -> T:
        last_error: str | None = None

        for _ in range(self._max_retries + 1):
            response = await self._generate(
                model=model,
                contents=json.dumps(user_content, ensure_ascii=False),
                config={
                    "system_instruction": system_prompt,
                    "temperature": temperature,
                    "response_mime_type": "application/json",
                    "response_schema": output_schema,
                },
            )

            parsed = getattr(response, "parsed", None)
            if isinstance(parsed, output_schema):
                return parsed

            try:
                return output_schema.model_validate_json(response.text)
            except Exception as exc:  # noqa: BLE001 - 스키마 검증 실패는 재시도 대상
                last_error = str(exc)
                continue

        raise SchemaViolationError(
            f"LLM output did not match {output_schema.__name__} "
            f"after {self._max_retries + 1} attempts: {last_error}"
        )


def create_llm_client(provider: str, api_key: str | None = None) -> "LLMClient":
    if provider == "anthropic":
        return AnthropicLLMClient(api_key=api_key)
    if provider == "gemini":
        if api_key is not None:
            return GeminiLLMClient(api_key=api_key)
        keys, labels = gemini_keys_from_env()
        if keys:
            return GeminiLLMClient(api_keys=keys, key_labels=labels)
        return GeminiLLMClient()  # SDK 기본 동작(GOOGLE_API_KEY 등)
    if provider == "template":
        from meerkat.llm.template_client import TemplateLLMClient

        return TemplateLLMClient()
    raise ValueError(f"unknown LLM provider: {provider}")


def gemini_keys_from_env(environ: dict | None = None) -> tuple[list[str], list[str]]:
    """사용할 Gemini 키 목록과 로그용 라벨(값이 아닌 이름)을 만든다.

    우선순위: GEMINI_API_KEYS="k1,k2"(명시 목록) → 없으면 GEMINI_API_KEY로 시작하는 모든 환경변수
    (GEMINI_API_KEY가 맨 앞, 나머지는 이름순). 같은 값은 한 번만 쓴다.
    """
    env = os.environ if environ is None else environ
    explicit = [k.strip() for k in env.get("GEMINI_API_KEYS", "").split(",") if k.strip()]
    if explicit:
        return explicit, [f"GEMINI_API_KEYS[{i}]" for i in range(len(explicit))]
    names = sorted(n for n in env if n.startswith("GEMINI_API_KEY") and n != "GEMINI_API_KEYS")
    if "GEMINI_API_KEY" in names:
        names.remove("GEMINI_API_KEY")
        names.insert(0, "GEMINI_API_KEY")
    keys: list[str] = []
    labels: list[str] = []
    for name in names:
        value = (env.get(name) or "").strip()
        if value and value not in keys:
            keys.append(value)
            labels.append(name)
    return keys, labels
