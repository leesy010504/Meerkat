"""오케스트레이터 의사결정 감사 로그.

룰 하나가 나오기까지 어떤 판단이 있었는지(관계 판단 결과, 후보 수, 각 후보의 검증 결과와
적용된 결정적 리라이트, 수리 횟수와 유형, 역할 그룹 확정 경로)를 순서대로 남긴다.
용도는 세 가지다: PR/제안서 본문의 "검증 과정" 항목, 평가(ablation)에서 수리 횟수·실패 유형
집계, 그리고 문제가 생겼을 때 사후 추적. LLM 자유 텍스트(reasoning 등)도 들어가지만 이 로그는
사람이 읽거나 집계하는 용도일 뿐 어떤 프롬프트의 입력도 되지 않는다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class DecisionTrace:
    context: dict[str, Any] = field(default_factory=dict)  # metric/src_ip 등 호출자가 채우는 식별 정보
    events: list[dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def record(self, event: str, **fields: Any) -> None:
        self.events.append({
            "t": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **{k: _jsonable(v) for k, v in fields.items()},
        })

    # ---- 집계 ----------------------------------------------------------------------------

    def count(self, event: str) -> int:
        return sum(1 for e in self.events if e["event"] == event)

    def llm_calls(self) -> int:
        return sum(1 for e in self.events if e["event"] in ("relation_assess", "generate", "repair", "select"))

    def calibrations(self) -> list[dict]:
        return [e for e in self.events if e["event"] == "threshold_calibration" and e.get("ok")]

    def repair_types(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.events:
            if e["event"] == "repair":
                out[e["failure_type"]] = out.get(e["failure_type"], 0) + 1
        return out

    def outcome(self) -> str | None:
        for e in reversed(self.events):
            if e["event"] == "outcome":
                return e.get("result")
        return None

    # ---- 출력 ----------------------------------------------------------------------------

    def to_record(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "context": self.context,
            "outcome": self.outcome(),
            "llm_calls": self.llm_calls(),
            "verify_runs": self.count("verify"),
            "repairs": self.repair_types(),
            "events": self.events,
        }

    def append_jsonl(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(self.to_record(), ensure_ascii=False) + "\n")
        return path

    def summary_lines(self) -> list[str]:
        """제안서용 한 줄 요약 목록."""
        lines: list[str] = []
        for e in self.events:
            kind = e["event"]
            if kind == "injection_filter":
                lines.append(f"인젝션 필터: {len(e['blanked_fields'])}개 필드 비움" if e["blanked_fields"] else "인젝션 필터: 통과")
            elif kind == "already_covered_check":
                lines.append(f"기존 룰셋 선검사({e['rules']}개 룰): " + (f"sid {e['covering_sid']}가 이미 탐지" if e.get("covering_sid") else "미커버"))
            elif kind == "relation_assess":
                lines.append(f"관계 판단: {'변종 (sid ' + str(e['matched_sid']) + ')' if e['is_variant'] else '신규 유형'}" + (" [강제 신규]" if e.get("forced") else ""))
            elif kind == "generate":
                lines.append(f"룰 생성: 후보 {e['candidates']}개")
            elif kind == "verify":
                status = "통과" if e["passed"] else f"실패 ({e['failure_kind']})"
                fixes = f", 결정적 리라이트 {e['applied_fixes']}" if e.get("applied_fixes") else ""
                lines.append(f"검증 #{e['attempt'] + 1}: {status}{fixes}")
            elif kind == "repair":
                lines.append(f"LLM 수리 ({e['failure_type']})")
            elif kind == "threshold_calibration":
                lines.append(
                    f"threshold 재생 보정: count {e['from_count']} → {e['to_count']} (LLM 없이, 재생 {e['replays']}회)"
                    if e.get("ok") else f"threshold 재생 보정 불가 ({e.get('reason')})"
                )
            elif kind == "select":
                lines.append(f"후보 선택: {e['passing']}개 중 1개")
            elif kind == "role_group":
                lines.append(f"역할 그룹: {e['group']}" + (f" (힌트 {e['hint']} 교정)" if e.get("hint") != e["group"] else ""))
            elif kind == "rollback":
                lines.append(f"롤백 #{e['count']}: 관계 판단으로 되돌림")
            elif kind == "outcome":
                lines.append(f"결과: {e['result']}" + (f" sid {e['sid']}" if e.get("sid") else ""))
        return lines


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)
