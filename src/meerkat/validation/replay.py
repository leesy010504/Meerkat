import json
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from meerkat.validation.suricata_env import suricata_set_args


class ReplayResult(BaseModel):
    ok: bool
    target: Literal["attack", "benign"]
    triggered_sids: list[int]
    raw_output: str
    # 알럿을 낸 플로우 샘플(5-tuple + http/dns 요약, pcap 이름). 오탐 수리 프롬프트에
    # "어떤 정상 플로우가 걸렸는지"를 구체적으로 보여주기 위한 것. 최대 MAX_ALERT_SAMPLES개.
    alert_samples: list[dict] = []


MAX_ALERT_SAMPLES = 5


# (룰, pcap 목록+mtime, 바이너리) → 결과. 같은 후보를 attack/benign으로 두 번, 수리 루프에서 여러 번,
# ablation에서 조건마다 다시 재생하는데 Suricata가 9MB pcap을 읽는 데 수 초씩 걸린다. 결과는 결정적이다.
_REPLAY_CACHE: dict[tuple, "ReplayResult"] = {}
_REPLAY_CACHE_MAX = 512


def clear_replay_cache() -> None:
    _REPLAY_CACHE.clear()


def _cache_key(rule_text: str, pcap_paths: list[str], suricata_binary: str) -> tuple:
    stamps = []
    for path in pcap_paths:
        try:
            st = Path(path).stat()
            stamps.append((path, st.st_mtime_ns, st.st_size))
        except OSError:
            stamps.append((path, None, None))
    return (rule_text, tuple(stamps), suricata_binary)


def replay_rule(
    rule_text: str,
    target: Literal["attack", "benign"],
    pcap_paths: list[str],
    suricata_binary: str = "suricata",
) -> ReplayResult:
    key = _cache_key(rule_text, pcap_paths, suricata_binary)
    cached = _REPLAY_CACHE.get(key)
    if cached is not None:
        ok = bool(cached.triggered_sids) if target == "attack" else not cached.triggered_sids
        return cached.model_copy(update={"target": target, "ok": ok})
    result = _replay_rule_uncached(rule_text, target, pcap_paths, suricata_binary)
    if len(_REPLAY_CACHE) >= _REPLAY_CACHE_MAX:
        _REPLAY_CACHE.pop(next(iter(_REPLAY_CACHE)))
    _REPLAY_CACHE[key] = result
    return result


def _replay_rule_uncached(
    rule_text: str,
    target: Literal["attack", "benign"],
    pcap_paths: list[str],
    suricata_binary: str = "suricata",
) -> ReplayResult:
    with tempfile.TemporaryDirectory() as tmp:
        rule_path = Path(tmp) / "test.rules"
        rule_path.write_text(rule_text)

        triggered: set[int] = set()
        outputs: list[str] = []
        samples: list[dict] = []

        for pcap_path in pcap_paths:
            log_dir = tempfile.mkdtemp(dir=tmp)
            # -k none: 체크섬 검증을 끈다 (루프백 캡처는 체크섬이 무효할 수 있음)
            # --runmode single: 오프라인 pcap을 기본(autofp) 멀티스레드로 돌리면 스레드마다 패킷 시각이
            # 어긋나 threshold/detection_filter의 seconds 창이 틀어진다. 분당 패킷 120개인 저속 스캔이
            # "60초에 280개" 룰을 울리는 식이라, threshold 룰의 트리거/오탐 판정이 실행마다 달랐다.
            # 단일 스레드는 패킷 순서대로 처리해 창이 정확하고, 작은 pcap에선 오히려 빠르다.
            # --set vars.address-groups.*: 루프백 캡처에서도 $HOME_NET/$EXTERNAL_NET 룰이
            # 매칭되도록 검증용 주소 그룹을 쓴다 (suricata_env.py 참조)
            result = subprocess.run(
                [
                    suricata_binary, "-S", str(rule_path), "-r", pcap_path, "-l", log_dir,
                    "-k", "none", "--runmode", "single", *suricata_set_args(),
                ],
                capture_output=True,
                text=True,
            )
            outputs.append(result.stdout + result.stderr)
            sids, pcap_samples = _alerts_from_eve(Path(log_dir) / "eve.json", Path(pcap_path).name)
            triggered |= sids
            if len(samples) < MAX_ALERT_SAMPLES:
                samples.extend(pcap_samples[: MAX_ALERT_SAMPLES - len(samples)])

        ok = bool(triggered) if target == "attack" else not triggered

        return ReplayResult(
            ok=ok,
            target=target,
            triggered_sids=sorted(triggered),
            raw_output="\n".join(outputs),
            alert_samples=samples,
        )


def _triggered_sids(eve_path: Path) -> set[int]:
    return _alerts_from_eve(eve_path, "")[0]


_SAMPLE_TOP_KEYS = ("src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto")
_SAMPLE_HTTP_KEYS = ("hostname", "url", "http_method", "http_user_agent", "status")


def _alerts_from_eve(eve_path: Path, pcap_name: str) -> tuple[set[int], list[dict]]:
    if not eve_path.exists():
        return set(), []

    sids: set[int] = set()
    samples: list[dict] = []
    seen_flows: set[tuple] = set()
    for line in eve_path.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") != "alert":
            continue
        sid = event.get("alert", {}).get("signature_id")
        if sid is None:
            continue
        sids.add(int(sid))

        flow_key = tuple(event.get(k) for k in _SAMPLE_TOP_KEYS)
        if flow_key in seen_flows or len(samples) >= MAX_ALERT_SAMPLES:
            continue
        seen_flows.add(flow_key)
        sample = {k: event[k] for k in _SAMPLE_TOP_KEYS if k in event}
        sample["sid"] = int(sid)
        if pcap_name:
            sample["pcap"] = pcap_name
        http = event.get("http")
        if isinstance(http, dict):
            sample["http"] = {k: http[k] for k in _SAMPLE_HTTP_KEYS if k in http}
        dns = event.get("dns")
        if isinstance(dns, dict):
            sample["dns"] = {k: dns[k] for k in ("rrname", "rrtype") if k in dns}
        tls = event.get("tls")
        if isinstance(tls, dict) and "sni" in tls:
            sample["tls"] = {"sni": tls["sni"]}
        samples.append(sample)
    return sids, samples
