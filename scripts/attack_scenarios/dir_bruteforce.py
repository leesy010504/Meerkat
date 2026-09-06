import argparse
from pathlib import Path
from urllib.parse import urlparse

from _capture import capture_while


def run_dir_bruteforce(
    target_url: str,
    wordlist: str = "tests/fixtures/wordlist.txt",
    output_dir: str = "pcaps/attack",
    interface: str = "any",
) -> str:
    """gobuster로 디렉토리 탐색을 재현한다."""
    output_path = Path(output_dir) / "dir_bruteforce.pcap"
    host = urlparse(target_url).hostname or target_url
    return capture_while(
        ["gobuster", "dir", "-u", target_url, "-w", wordlist, "-q"],
        output_path,
        interface=interface,
        host_filter=host,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="gobuster 디렉토리 탐색 재현 + pcap 캡처")
    parser.add_argument("target_url")
    parser.add_argument("--wordlist", default="tests/fixtures/wordlist.txt")
    parser.add_argument("--output-dir", default="pcaps/attack")
    parser.add_argument("--interface", default="any")
    args = parser.parse_args()
    print(run_dir_bruteforce(args.target_url, args.wordlist, args.output_dir, args.interface))
