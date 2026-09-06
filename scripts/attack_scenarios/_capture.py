import subprocess
import time
from pathlib import Path


def capture_while(cmd: list[str], output_path: str | Path, interface: str = "any", host_filter: str | None = None) -> str:
    """tcpdump로 캡처하면서 cmd를 실행한다."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    filter_expr = f"host {host_filter}" if host_filter else ""
    tcpdump_cmd = ["tcpdump", "-i", interface, "-w", str(output_path)]
    if filter_expr:
        tcpdump_cmd.append(filter_expr)

    capture = subprocess.Popen(tcpdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)  # tcpdump 기동 대기

    try:
        subprocess.run(cmd, check=True)
    finally:
        time.sleep(1)
        capture.terminate()
        capture.wait()

    return str(output_path)
