"""표준 dig로 로컬 리졸버에 많은 DNS 질의를 보내며 pcap을 캡처한다.

dns-flood 역할 그룹(dns_query_rate_per_src 지표)의 검증 pcap을 만드는 용도. 로컬 dnsmasq
타겟(docker-compose target-dns)에만 질의하며, 그 리졸버는 업스트림이 없어(no-resolv) 외부로
질의를 내보내지 않는다. 각 질의는 고유 서브도메인이라 리졸버 캐시에 걸리지 않고 매번 실제
질의가 나간다 — 단일 출발지에서 짧은 시간에 질의가 몰리는 패턴을 재현한다.

    uv run python scripts/attack_scenarios/dns_query_burst.py --server 127.0.0.1 --count 400
"""

import argparse
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _capture import capture_while  # noqa: E402


def _run_queries(server: str, port: int, count: int, domain: str) -> None:
    for _ in range(count):
        label = uuid.uuid4().hex[:12]
        subprocess.run(
            ["dig", f"@{server}", "-p", str(port), f"{label}.{domain}", "A",
             "+tries=1", "+time=1", "+short"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )


def run_dns_query_burst(server: str = "127.0.0.1", port: int = 53, count: int = 400,
                        domain: str = "flood-test.example", output_dir: str = "pcaps/attack",
                        interface: str = "lo0") -> str:
    output_path = Path(output_dir) / "dns_query_burst.pcap"
    this = sys.executable
    helper = str(Path(__file__).resolve())
    path = capture_while(
        [this, helper, "_run", server, str(port), str(count), domain],
        output_path, interface=interface, host_filter=None,
    )
    # 루프백에는 다른 로컬 서비스 트래픽도 섞여 들어오므로 DNS 포트만 남긴다
    trimmed = output_path.with_suffix(".tmp.pcap")
    subprocess.run(["tcpdump", "-r", str(output_path), "-w", str(trimmed), f"udp port {port}"],
                   check=True, capture_output=True)
    trimmed.replace(output_path)
    return path


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "_run":
        _run_queries(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
        sys.exit(0)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--domain", default="flood-test.example")
    parser.add_argument("--output-dir", default="pcaps/attack")
    parser.add_argument("--interface", default="lo0")
    args = parser.parse_args()
    print(run_dns_query_burst(args.server, args.port, args.count, args.domain, args.output_dir, args.interface))
