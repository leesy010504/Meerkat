from pathlib import Path
from typing import Literal

from meerkat.validation.replay import ReplayResult, replay_rule
from meerkat.validation.syntax import SyntaxResult, check_rule_syntax


async def rule_syntax_check(rule_text: str, suricata_binary: str = "suricata") -> SyntaxResult:
    return check_rule_syntax(rule_text, suricata_binary)


async def rule_replay(
    rule_text: str,
    target: Literal["attack", "benign"],
    pcap_paths: list[str] | None = None,
    pcaps_attack_dir: str = "pcaps/attack",
    pcaps_benign_dir: str = "pcaps/benign",
    suricata_binary: str = "suricata",
) -> ReplayResult:
    if pcap_paths is None:
        default_dir = pcaps_attack_dir if target == "attack" else pcaps_benign_dir
        pcap_paths = [str(p) for p in Path(default_dir).glob("*.pcap")]

    return replay_rule(rule_text, target, pcap_paths, suricata_binary)


def allocate_sid(existing_sids: set[int], sid_range: tuple[int, int] = (1000000, 1999999)) -> int:
    for candidate in range(sid_range[0], sid_range[1] + 1):
        if candidate not in existing_sids:
            return candidate
    raise RuntimeError("no available sid in local range")
