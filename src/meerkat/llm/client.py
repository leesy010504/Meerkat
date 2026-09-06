import asyncio
import json
from typing import Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

_TRANSIENT_BACKOFF_SECONDS = [2, 5, 10]


async def _call_with_transient_retry(fn):
    """429/5xx 등 일시적 서버 에러를 백오프하며 재시도한다."""
    last_exc: Exception | None = None
    for delay in [*_TRANSIENT_BACKOFF_SECONDS, None]:
        try:
            return await fn()
        except Exception as exc:  # noqa: BLE001 - 어떤 SDK든 동일하게 처리
            status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
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
                    temperature=temperature,
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


class GeminiLLMClient:
    def __init__(self, api_key: str | None = None, max_retries: int = 2):
        from google import genai

        self._client = genai.Client(api_key=api_key)
        self._max_retries = max_retries

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
            response = await _call_with_transient_retry(
                lambda: self._client.aio.models.generate_content(
                    model=model,
                    contents=json.dumps(user_content, ensure_ascii=False),
                    config={
                        "system_instruction": system_prompt,
                        "temperature": temperature,
                        "response_mime_type": "application/json",
                        "response_schema": output_schema,
                    },
                )
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
        return GeminiLLMClient(api_key=api_key)
    raise ValueError(f"unknown LLM provider: {provider}")
