"""검증 코퍼스 구성 — 역할 그룹별로 "울려야 하는 pcap"과 "조용해야 하는 pcap"을 나눈다.

기존 검증은 attack_pcaps 중 하나라도 알럿이 나면 트리거 통과였다. 그러면 gobuster 룰이 포트스캔
pcap에서 울려도 통과하고, 반대로 너무 넓은 룰(모든 SYN을 세는 룰)이 다른 공격 pcap에서 울리는
것도 잡지 못한다. 매니페스트(pcaps/attack/manifest.yaml)로 pcap을 역할 그룹에 묶고:

  positive  = 그 그룹의 pcap (+ 스케줄러가 추출한 대표 pcap)
  negative  = 정상 pcap 전부 + 다른 그룹의 공격 pcap   ← 둘 다 알럿 0이어야 통과

VerifyContext의 필드 이름은 그대로 두고(attack_pcaps / benign_pcaps) negative 전체를 benign_pcaps에
넣는다 — 오케스트레이터 변경 없이 적용되고, 오탐 샘플에는 pcap 이름이 붙어 있어 수리 프롬프트가
"다른 공격 pcap에 걸렸다"는 것을 알 수 있다.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from meerkat.agent.orchestrator import VerifyContext

DEFAULT_MANIFEST = "pcaps/attack/manifest.yaml"


def load_manifest(attack_dir: str | Path, manifest_name: str = "manifest.yaml") -> dict[str, dict]:
    """{pcap 파일명: {role_group, metric, scenario}}. 매니페스트가 없으면 빈 dict."""
    path = Path(attack_dir) / manifest_name
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text()) or {}
    return {name: dict(meta or {}) for name, meta in raw.items()}


def pcaps_for_group(attack_dir: str | Path, manifest: dict[str, dict], role_group: str) -> list[str]:
    return _select(attack_dir, manifest, "role_group", role_group)


def pcaps_for_metric(attack_dir: str | Path, manifest: dict[str, dict], metric: str) -> list[str]:
    return _select(attack_dir, manifest, "metric", metric)


def _select(attack_dir: str | Path, manifest: dict[str, dict], key: str, value: str) -> list[str]:
    return sorted(
        str(Path(attack_dir) / name) for name, meta in manifest.items()
        if meta.get(key) == value and (Path(attack_dir) / name).exists()
    )


def build_verify_context(
    role_group: str,
    attack_dir: str | Path,
    benign_dir: str | Path,
    manifest: dict[str, dict] | None = None,
    suricata_binary: str = "suricata",
    repr_pcap: str | None = None,
    cross_group_negative: bool = True,
    metric: str | None = None,
) -> VerifyContext:
    """VerifyContext를 만든다.

    positive는 **실제로 트리거된 지표(metric)**의 pcap을 우선 쓰고, 없으면 역할 그룹 힌트의 pcap을 쓴다.
    힌트는 틀릴 수 있다 — 스케줄러는 conn_count_per_src_port를 "scanning"으로 힌트하지만 그 지표가 실제로
    잡는 건 SSH 브루트포스다. 힌트만 믿으면 맞는 SSH 룰을 SSH pcap을 negative로 두고 검증해 떨어뜨린다.
    negative는 positive와 **다른 역할 그룹**의 매니페스트 pcap이다. 둘 다 없으면 예전 방식(전부 positive).
    """
    manifest = load_manifest(attack_dir) if manifest is None else manifest
    all_attack = sorted(str(p) for p in Path(attack_dir).glob("*.pcap"))
    benign = sorted(str(p) for p in Path(benign_dir).glob("*.pcap"))

    positive = pcaps_for_metric(attack_dir, manifest, metric) if metric else []
    if not positive:
        positive = pcaps_for_group(attack_dir, manifest, role_group)
    if not positive:
        positive = list(all_attack)
        negative_attack: list[str] = []
    else:
        positive_groups = {manifest[Path(p).name].get("role_group") for p in positive if Path(p).name in manifest}
        # 매니페스트에 있고 positive와 다른 그룹인 pcap만 negative — 매니페스트에 없는 pcap은 성격을 모르니 제외
        negative_attack = [
            p for p in all_attack
            if Path(p).name in manifest and p not in positive
            and manifest[Path(p).name].get("role_group") not in positive_groups
        ] if cross_group_negative else []

    if repr_pcap and repr_pcap not in positive:
        positive = [*positive, repr_pcap]

    return VerifyContext(
        attack_pcaps=positive,
        benign_pcaps=[*benign, *negative_attack],
        suricata_binary=suricata_binary,
    )
