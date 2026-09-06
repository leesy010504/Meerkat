import subprocess
import tempfile
from pathlib import Path

from pydantic import BaseModel


class SyntaxResult(BaseModel):
    ok: bool
    raw_output: str


def check_rule_syntax(rule_text: str, suricata_binary: str = "suricata") -> SyntaxResult:
    with tempfile.TemporaryDirectory() as tmp:
        rule_path = Path(tmp) / "test.rules"
        rule_path.write_text(rule_text)

        result = subprocess.run(
            [suricata_binary, "-T", "-S", str(rule_path), "-l", tmp],
            capture_output=True,
            text=True,
        )

    return SyntaxResult(
        ok=result.returncode == 0,
        raw_output=result.stdout + result.stderr,
    )
