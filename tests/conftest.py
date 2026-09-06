from dotenv import load_dotenv

load_dotenv()


class FakeLLMClient:
    """스키마별로 큐에 넣어둔 응답을 순서대로 꺼내준다. 큐가 비면 마지막 값을 반복."""

    def __init__(self):
        self.queues: dict[type, list] = {}
        self.calls: list[type] = []

    def queue(self, *outputs) -> None:
        schema = type(outputs[0])
        self.queues.setdefault(schema, []).extend(outputs)

    async def complete_structured(self, system_prompt, user_content, output_schema, model, temperature=0.0):
        self.calls.append(output_schema)
        bucket = self.queues.get(output_schema, [])
        if not bucket:
            raise AssertionError(f"no queued response for {output_schema.__name__}")
        return bucket.pop(0) if len(bucket) > 1 else bucket[0]
