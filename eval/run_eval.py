import argparse
import json
from pathlib import Path

from meerkat.validation.replay import replay_rule

from eval.metrics import (
    rule_count,
    rule_usability_rate,
    security_effectiveness,
    semantic_similarity,
    syntax_accuracy,
)


def load_rules(rules_dir: str) -> list[str]:
    rules: list[str] = []
    for path in Path(rules_dir).glob("*.rules"):
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(line)
    return rules


def run_eval(
    generated_dir: str,
    reference_dir: str,
    attack_pcaps_dir: str,
    benign_pcaps_dir: str,
    suricata_binary: str = "suricata",
) -> dict:
    generated = load_rules(generated_dir)
    reference = load_rules(reference_dir)

    attack_pcaps = [str(p) for p in Path(attack_pcaps_dir).glob("*.pcap")]
    benign_pcaps = [str(p) for p in Path(benign_pcaps_dir).glob("*.pcap")]

    triggered_on_attack = 0
    false_positives = 0
    for rule_text in generated:
        if replay_rule(rule_text, "attack", attack_pcaps, suricata_binary).ok:
            triggered_on_attack += 1
        if not replay_rule(rule_text, "benign", benign_pcaps, suricata_binary).ok:
            false_positives += 1

    detection_rate = triggered_on_attack / len(generated) if generated else 0.0
    false_positive_rate = false_positives / len(generated) if generated else 0.0

    ss_scores = [
        max((semantic_similarity(rule_text, ref) for ref in reference), default=0.0)
        for rule_text in generated
    ] if reference else []

    return {
        "SA": syntax_accuracy(generated, suricata_binary),
        "SS": (sum(ss_scores) / len(ss_scores)) if ss_scores else None,
        "SE": security_effectiveness(detection_rate, false_positive_rate),
        # ADR/DL은 배포 후 별도로 계산한다
        "ADR": None,
        "RC": rule_count(generated),
        "RUR": rule_usability_rate(generated, suricata_binary),
        "DL": None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="평가 지표 산출")
    parser.add_argument("--generated-dir", default="rules")
    parser.add_argument("--reference-dir", required=True, help="ET Open 등 참조 룰셋 디렉토리")
    parser.add_argument("--attack-pcaps-dir", default="pcaps/attack")
    parser.add_argument("--benign-pcaps-dir", default="pcaps/benign")
    parser.add_argument("--suricata-binary", default="suricata")
    args = parser.parse_args()

    result = run_eval(
        args.generated_dir,
        args.reference_dir,
        args.attack_pcaps_dir,
        args.benign_pcaps_dir,
        args.suricata_binary,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
