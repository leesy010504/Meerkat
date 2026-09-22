"""브라우저 User-Agent로 위장한 디렉토리 탐색을 재현하고 pcap을 캡처한다.

dir_bruteforce.py(gobuster 기본 UA)의 어려운 변형. User-Agent를 정상 브라우징 pcap
(pcaps/benign/web_browsing.pcap)과 똑같은 Chrome 문자열로 바꾸고 스레드 수를 낮춰서,
"도구 UA 문자열 매칭"이나 "요청 수 임계값"만으로는 정상 브라우징과 구분되지 않게 만든다.
남는 신호는 단일 출발지에서 짧은 시간에 쏟아지는 404 응답 비율이다.

로컬 nginx 타겟(docker-compose target-nginx)에만 요청한다.

    MEERKAT_NGINX_PORT=18080 docker compose -f docker-compose.dev.yml up -d target-nginx
    uv run python scripts/attack_scenarios/ua_spoofed_dirbust.py http://127.0.0.1:18080
"""

import argparse
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from _capture import capture_while  # noqa: E402

BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")


def run_ua_spoofed_dirbust(target_url: str, wordlist: str = "tests/fixtures/wordlist_large.txt",
                           output_dir: str = "pcaps/attack", interface: str = "lo0",
                           threads: int = 2, delay: str = "50ms") -> str:
    output_path = Path(output_dir) / "ua_spoofed_dirbust.pcap"
    parsed = urlparse(target_url)
    port = parsed.port or 80
    capture_while(
        ["gobuster", "dir", "-u", target_url, "-w", wordlist, "-q", "--no-error",
         "-a", BROWSER_UA, "-t", str(threads), "--delay", delay],
        output_path, interface=interface, host_filter=None,
    )
    # 루프백의 다른 로컬 서비스 트래픽은 버리고 타겟 포트만 남긴다
    trimmed = output_path.with_suffix(".tmp.pcap")
    subprocess.run(["tcpdump", "-r", str(output_path), "-w", str(trimmed), f"tcp port {port}"],
                   check=True, capture_output=True)
    trimmed.replace(output_path)
    return str(output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target_url")
    parser.add_argument("--wordlist", default="tests/fixtures/wordlist_large.txt")
    parser.add_argument("--output-dir", default="pcaps/attack")
    parser.add_argument("--interface", default="lo0")
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--delay", default="50ms")
    args = parser.parse_args()
    print(run_ua_spoofed_dirbust(args.target_url, args.wordlist, args.output_dir, args.interface,
                                 args.threads, args.delay))
