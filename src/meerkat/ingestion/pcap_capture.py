"""Suricata pcap-log 회전 파일에서 특정 플로우의 패킷만 5-tuple과
타임스탬프 기준으로 추출한다."""

import re
import subprocess
from pathlib import Path

_ROTATION_TIMESTAMP_RE = re.compile(r"\.(\d{10,})$")


def list_pcap_log_files(directory: str | Path) -> list[tuple[float, Path]]:
    """Suricata pcap-log 회전 파일을 타임스탬프 기준으로 정렬해 반환한다.
    파일명이 `<prefix>.pcap.<unix_timestamp>` 형태라고 가정한다(기본 설정)."""
    files: list[tuple[float, Path]] = []
    for path in Path(directory).glob("*.pcap.*"):
        match = _ROTATION_TIMESTAMP_RE.search(path.name)
        if match:
            files.append((float(match.group(1)), path))
    return sorted(files, key=lambda item: item[0])


def find_covering_files(
    files: list[tuple[float, Path]], start_ts: float, end_ts: float
) -> list[Path]:
    """[start_ts, end_ts] 구간과 겹치는 회전 파일들을 고른다."""
    covering: list[Path] = []
    for i, (file_ts, path) in enumerate(files):
        next_ts = files[i + 1][0] if i + 1 < len(files) else float("inf")
        if file_ts <= end_ts and next_ts >= start_ts:
            covering.append(path)
    return covering


def extract_flow_pcap(
    source_pcaps: list[Path | str],
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: str,
    output_path: str | Path,
) -> str:
    """회전 파일들에서 5-tuple에 해당하는 패킷만 뽑아 새 pcap으로 만든다."""
    if not source_pcaps:
        raise ValueError("no source pcap files to extract from")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if len(source_pcaps) == 1:
        merged_source = Path(source_pcaps[0])
        cleanup_merged = False
    else:
        merged_source = output_path.with_name(output_path.stem + ".merged.pcap")
        subprocess.run(
            ["mergecap", "-w", str(merged_source), *[str(p) for p in source_pcaps]],
            check=True,
            capture_output=True,
        )
        cleanup_merged = True

    bpf_filter = (
        f"{proto.lower()} and host {src_ip} and host {dst_ip} "
        f"and port {src_port} and port {dst_port}"
    )

    try:
        subprocess.run(
            ["tcpdump", "-r", str(merged_source), "-w", str(output_path), bpf_filter],
            check=True,
            capture_output=True,
        )
    finally:
        if cleanup_merged:
            merged_source.unlink(missing_ok=True)

    return str(output_path)


def build_suricata_pcap_log_config(
    filename: str = "log.pcap",
    limit_mb: int = 1000,
    max_files: int = 200,
) -> dict:
    """suricata.yaml에 합칠 pcap-log 설정 조각을 만든다."""
    return {
        "pcap-log": {
            "enabled": True,
            "filename": filename,
            "limit": f"{limit_mb}mb",
            "max-files": max_files,
            "compression": "none",
            "mode": "normal",
            "use-stream-depth": False,
            "honor-pass-rules": False,
        }
    }
