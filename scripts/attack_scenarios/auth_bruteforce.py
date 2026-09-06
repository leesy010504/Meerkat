import argparse
from pathlib import Path

from _capture import capture_while


def run_auth_bruteforce(
    target: str,
    service: str,
    userlist: str,
    passlist: str,
    port: int | None = None,
    output_dir: str = "pcaps/attack",
    interface: str = "any",
) -> str:
    output_path = Path(output_dir) / "auth_bruteforce.pcap"
    cmd = ["hydra", "-L", userlist, "-P", passlist]
    if port is not None:
        cmd += ["-s", str(port)]
    cmd += [target, service]
    return capture_while(cmd, output_path, interface=interface, host_filter=target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="hydra 인증 브루트포스 재현 + pcap 캡처")
    parser.add_argument("target")
    parser.add_argument("service", help="예: ssh, ftp, http-post-form")
    parser.add_argument("--userlist", required=True)
    parser.add_argument("--passlist", required=True)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--output-dir", default="pcaps/attack")
    parser.add_argument("--interface", default="any")
    args = parser.parse_args()
    print(
        run_auth_bruteforce(
            args.target, args.service, args.userlist, args.passlist,
            args.port, args.output_dir, args.interface,
        )
    )
