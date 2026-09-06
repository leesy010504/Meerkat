import argparse
from pathlib import Path

from _capture import capture_while


def run_port_scan(target: str, output_dir: str = "pcaps/attack", interface: str = "any") -> str:
    output_path = Path(output_dir) / "port_scan.pcap"
    return capture_while(
        ["nmap", "-T4", "-p-", target],
        output_path,
        interface=interface,
        host_filter=target,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="nmap 포트 스캔 재현 + pcap 캡처")
    parser.add_argument("target")
    parser.add_argument("--output-dir", default="pcaps/attack")
    parser.add_argument("--interface", default="any")
    args = parser.parse_args()
    print(run_port_scan(args.target, args.output_dir, args.interface))
