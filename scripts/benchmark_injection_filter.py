"""필드별 오탐률(FPR)/탐지율(TPR)을 측정한다."""

import json
from collections import defaultdict
from pathlib import Path

from meerkat.security.injection_filter import FIELD_USE_SECONDARY, check_injection

FIXTURES = Path("tests/fixtures")

BENIGN_SOURCES = {
    "http.uri": FIXTURES / "benign_data" / "http_uri.txt",
    "http.user_agent": FIXTURES / "benign_data" / "http_user_agent.txt",
    "http.host": FIXTURES / "benign_data" / "domains.txt",
    "dns.rrname": FIXTURES / "benign_data" / "domains.txt",
    "tls.sni": FIXTURES / "benign_data" / "domains.txt",
}


def load_benign(field: str) -> list[str]:
    return [line.strip() for line in BENIGN_SOURCES[field].read_text().splitlines() if line.strip()]


def load_attack() -> list[dict]:
    return json.loads((FIXTURES / "injection_data" / "synthetic_payloads.json").read_text())


def main() -> None:
    results = {"benign": defaultdict(list), "attack": defaultdict(list)}

    print("=== 정상 데이터 (오탐률 측정용) ===")
    for field, path in BENIGN_SOURCES.items():
        values = load_benign(field)
        use_secondary = FIELD_USE_SECONDARY.get(field, True)
        flagged = 0
        for value in values:
            r = check_injection(value, use_secondary=use_secondary)
            results["benign"][field].append(
                {"value": value, "is_injection": r.is_injection, "score": r.score}
            )
            if r.is_injection:
                flagged += 1
        fpr = flagged / len(values) if values else 0.0
        print(f"{field:20s} n={len(values):4d}  오탐 {flagged:4d}  FPR={fpr:.4f}")

    print()
    print("=== 합성 공격 데이터 (탐지율 측정용) ===")
    attack_payloads = load_attack()
    by_category: dict[str, list[dict]] = defaultdict(list)
    for p in attack_payloads:
        by_category[p["category"]].append(p)

    for category, payloads in by_category.items():
        detected = 0
        by_field_detected: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for p in payloads:
            use_secondary = FIELD_USE_SECONDARY.get(p["field_type"], True)
            r = check_injection(p["payload"], use_secondary=use_secondary)
            results["attack"][category].append(
                {
                    "field_type": p["field_type"],
                    "value": p["payload"],
                    "is_injection": r.is_injection,
                    "score": r.score,
                    "primary_score": r.primary_score,
                    "secondary_score": r.secondary_score,
                }
            )
            by_field_detected[p["field_type"]][1] += 1
            if r.is_injection:
                detected += 1
                by_field_detected[p["field_type"]][0] += 1

        tpr = detected / len(payloads) if payloads else 0.0
        print(f"{category:28s} n={len(payloads):3d}  탐지 {detected:3d}  TPR={tpr:.4f}")
        for field, (d, n) in sorted(by_field_detected.items()):
            print(f"    {field:20s} n={n:3d}  탐지 {d:3d}  TPR={d/n:.4f}")

    out_path = FIXTURES / "injection_data" / "benchmark_raw_results.json"
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n원본 결과 저장: {out_path}")


if __name__ == "__main__":
    main()
