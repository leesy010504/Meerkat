"""저속(low-and-slow) 포트 스캔을 재현하고 pcap을 캡처한다.

port_scan.py(nmap -T4 -p-)의 어려운 변형. 프로브 간격을 벌려 초당 1개 수준으로 낮추면
배포된 scanning 룰(60초에 SYN 200개)의 임계값 아래로 지나간다. 탐지하려면 더 긴 창을 써야 하는데,
그러면 정상 브라우징처럼 연결을 많이 여는 출발지와 겹치기 쉬워서 "SYN 개수"만으로는 오탐이 난다.
닫힌 포트에서 돌아오는 RST처럼 스캔에만 있는 신호를 찾아야 하는 시나리오다.

루프백(127.0.0.1)에만 connect 스캔(-sT, root 불필요)을 보낸다.

    uv run python scripts/attack_scenarios/slow_port_scan.py --ports 1-300 --scan-delay 1s
"""

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _capture import capture_while  # noqa: E402


def run_slow_port_scan(target: str = "127.0.0.1", ports: str = "1-300", scan_delay: str = "1s",
                       output_dir: str = "pcaps/attack", interface: str = "lo0") -> str:
    output_path = Path(output_dir) / "slow_port_scan.pcap"
    capture_while(
        ["nmap", "-sT", "-Pn", "-n", "--max-retries", "0", "--scan-delay", scan_delay, "-p", ports, target],
        output_path, interface=interface, host_filter=None,
    )
    # 스캔 대상 포트 범위의 TCP만 남긴다 (루프백의 다른 서비스 트래픽 제거)
    lo, _, hi = ports.partition("-")
    trimmed = output_path.with_suffix(".tmp.pcap")
    subprocess.run(["tcpdump", "-r", str(output_path), "-w", str(trimmed),
                    f"tcp and (dst portrange {lo}-{hi or lo} or src portrange {lo}-{hi or lo})"],
                   check=True, capture_output=True)
    trimmed.replace(output_path)
    return str(output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--ports", default="1-300")
    parser.add_argument("--scan-delay", default="1s")
    parser.add_argument("--output-dir", default="pcaps/attack")
    parser.add_argument("--interface", default="lo0")
    args = parser.parse_args()
    print(run_slow_port_scan(args.target, args.ports, args.scan_delay, args.output_dir, args.interface))
