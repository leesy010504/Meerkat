import json
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel


class ReplayResult(BaseModel):
    ok: bool
    target: Literal["attack", "benign"]
    triggered_sids: list[int]
    raw_output: str


def replay_rule(
    rule_text: str,
    target: Literal["attack", "benign"],
    pcap_paths: list[str],
    suricata_binary: str = "suricata",
) -> ReplayResult:
    with tempfile.TemporaryDirectory() as tmp:
        rule_path = Path(tmp) / "test.rules"
        rule_path.write_text(rule_text)

        triggered: set[int] = set()
        outputs: list[str] = []

        for pcap_path in pcap_paths:
            log_dir = tempfile.mkdtemp(dir=tmp)
            # -k none: 체크섬 검증을 끈다 (루프백 캡처는 체크섬이 무효할 수 있음)
            result = subprocess.run(
                [suricata_binary, "-S", str(rule_path), "-r", pcap_path, "-l", log_dir, "-k", "none"],
                capture_output=True,
                text=True,
            )
            outputs.append(result.stdout + result.stderr)
            triggered |= _triggered_sids(Path(log_dir) / "eve.json")

        ok = bool(triggered) if target == "attack" else not triggered

        return ReplayResult(
            ok=ok,
            target=target,
            triggered_sids=sorted(triggered),
            raw_output="\n".join(outputs),
        )


def _triggered_sids(eve_path: Path) -> set[int]:
    if not eve_path.exists():
        return set()

    sids: set[int] = set()
    for line in eve_path.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":
            sid = event.get("alert", {}).get("signature_id")
            if sid is not None:
                sids.add(int(sid))
    return sids
