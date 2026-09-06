"""pcap_capture 모듈의 회전 파일 탐색 및 5-tuple 추출 로직을 검증한다."""

import subprocess

import pytest

from meerkat.ingestion.pcap_capture import (
    extract_flow_pcap,
    find_covering_files,
    list_pcap_log_files,
)

SOURCE_PCAP = "pcaps/attack/auth_bruteforce.pcap"
FLOW = dict(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=53371, dst_port=2222, proto="tcp")


def _packet_count(pcap_path) -> int:
    result = subprocess.run(["tcpdump", "-nr", str(pcap_path)], capture_output=True, text=True)
    return len([line for line in result.stdout.splitlines() if line.strip()])


def test_list_pcap_log_files_parses_timestamp_suffix(tmp_path):
    (tmp_path / "log.pcap.1735689600").touch()
    (tmp_path / "log.pcap.1735689900").touch()
    (tmp_path / "unrelated.txt").touch()

    files = list_pcap_log_files(tmp_path)

    assert [ts for ts, _ in files] == [1735689600.0, 1735689900.0]


def test_find_covering_files_picks_overlapping_rotation_window():
    files = [(100.0, "a"), (200.0, "b"), (300.0, "c")]

    covering = find_covering_files(files, start_ts=150.0, end_ts=250.0)

    assert covering == ["a", "b"]


def test_find_covering_files_last_file_covers_to_infinity():
    files = [(100.0, "a"), (200.0, "b")]

    covering = find_covering_files(files, start_ts=500.0, end_ts=600.0)

    assert covering == ["b"]


def test_extract_flow_pcap_pulls_only_matching_flow(tmp_path):
    output_path = tmp_path / "flow.pcap"

    result = extract_flow_pcap([SOURCE_PCAP], **FLOW, output_path=output_path)

    assert result == str(output_path)
    extracted_count = _packet_count(output_path)
    source_count = _packet_count(SOURCE_PCAP)

    assert 0 < extracted_count < source_count


def test_extract_flow_pcap_merges_multiple_rotation_files(tmp_path):
    """회전 파일이 여러 개로 쪼개져 있어도 같은 결과가 나와야 한다."""
    part_prefix = tmp_path / "part"
    subprocess.run(
        ["editcap", "-c", "200", SOURCE_PCAP, f"{part_prefix}.pcap"],
        check=True, capture_output=True,
    )
    parts = sorted(tmp_path.glob("part_*.pcap"))
    assert len(parts) > 1

    single_output = tmp_path / "single.pcap"
    extract_flow_pcap([SOURCE_PCAP], **FLOW, output_path=single_output)

    merged_output = tmp_path / "merged.pcap"
    extract_flow_pcap(parts, **FLOW, output_path=merged_output)

    assert _packet_count(single_output) == _packet_count(merged_output)


def test_extract_flow_pcap_raises_on_empty_source_list(tmp_path):
    with pytest.raises(ValueError):
        extract_flow_pcap([], **FLOW, output_path=tmp_path / "x.pcap")
