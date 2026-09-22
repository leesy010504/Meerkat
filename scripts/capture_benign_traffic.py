"""정상(benign) 트래픽을 재현하면서 pcap으로 캡처한다 — 오탐(⑦) 검사 코퍼스용.

지금까지 pcaps/benign/normal_traffic.pcap은 48패킷짜리였다. 오탐 검사는 정상 트래픽이
풍부할수록 의미가 있으므로, 로컬 타겟(docker-compose.dev.yml)에 대한 평범한 사용 패턴을
몇 가지 재현한다:

  web_browsing  : 실제 브라우저 UA로 index → robots → login → admin 순회를 여러 번 (keep-alive 포함)
  ssh_normal    : SSH 서버에 정상적으로 접속해 배너만 교환 (브루트포스가 아닌 단발 접속)
  dns_tls       : 공개 리졸버에 A/AAAA 질의 몇 건 + 공개 사이트 한 곳 TLS 핸드셰이크

    uv run python scripts/capture_benign_traffic.py --output-dir pcaps/benign
"""

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "attack_scenarios"))
from _capture import capture_while  # noqa: E402

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
)


def _browse(base_url: str, rounds: int) -> None:
    pages = ["/", "/robots.txt", "/login.html", "/admin/", "/index.html", "/favicon.ico"]
    for _ in range(rounds):
        for page in pages:
            subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-A", BROWSER_UA, "-H", f"Referer: {base_url}/",
                 "-H", "Accept: text/html,application/xhtml+xml", base_url + page],
                check=False,
            )
            time.sleep(0.15)
        # keep-alive로 여러 페이지를 한 연결에서 받는 패턴
        subprocess.run(
            ["curl", "-s", "-A", BROWSER_UA,
             "-o", "/dev/null", base_url + "/",
             "-o", "/dev/null", base_url + "/robots.txt",
             "-o", "/dev/null", base_url + "/login.html"],
            check=False,
        )
        time.sleep(0.5)


def _ssh_banner(host: str, port: int, times: int) -> None:
    for _ in range(times):
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                sock.recv(256)  # 서버 배너
                sock.sendall(b"SSH-2.0-OpenSSH_9.8\r\n")
                time.sleep(0.3)
        except OSError:
            pass
        time.sleep(1.0)


def _dns_and_tls() -> None:
    for name in ("example.com", "www.wikipedia.org", "github.com", "pypi.org"):
        subprocess.run(["dig", "+short", "+time=2", "+tries=1", name, "A"], capture_output=True, check=False)
        subprocess.run(["dig", "+short", "+time=2", "+tries=1", name, "AAAA"], capture_output=True, check=False)
    subprocess.run(["curl", "-s", "-o", "/dev/null", "-A", BROWSER_UA, "https://example.com/"], check=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", default="pcaps/benign")
    parser.add_argument("--web-url", default="http://localhost:8080")
    parser.add_argument("--ssh-host", default="localhost")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--skip-external", action="store_true", help="DNS/TLS(외부 네트워크) 캡처 생략")
    parser.add_argument("--only", choices=["web", "ssh", "external"], default=None)
    args = parser.parse_args()
    out = Path(args.output_dir)

    this = sys.executable
    helper = str(Path(__file__).resolve())

    if args.only in (None, "web"):
        print(capture_while([this, helper, "_run", "browse", args.web_url, str(args.rounds)],
                            out / "web_browsing.pcap", interface="lo0", host_filter=None))
    if args.only in (None, "ssh"):
        print(capture_while([this, helper, "_run", "ssh", args.ssh_host, str(args.ssh_port)],
                            out / "ssh_normal.pcap", interface="lo0", host_filter=None))
    if args.only == "external":
        args.skip_external = False
    elif args.only is not None:
        args.skip_external = True
    if not args.skip_external:
        # macOS tcpdump은 -i any를 지원하지 않는다 — 기본 경로 인터페이스를 찾아 쓴다
        iface = _default_interface()
        print(capture_while([this, helper, "_run", "dnstls"], out / "dns_tls.pcap", interface=iface,
                            host_filter=None))


def _default_interface() -> str:
    result = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, check=False)
    for line in result.stdout.splitlines():
        if "interface:" in line:
            return line.split(":", 1)[1].strip()
    return "en0"


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "_run":
        kind = sys.argv[2]
        if kind == "browse":
            _browse(sys.argv[3], int(sys.argv[4]))
        elif kind == "ssh":
            _ssh_banner(sys.argv[3], int(sys.argv[4]), times=3)
        elif kind == "dnstls":
            _dns_and_tls()
        sys.exit(0)
    main()
