"""es_templates.py의 인덱스 템플릿/ILM 정책을 JSON 파일로 내보낸다."""

import argparse
import json
from pathlib import Path

from meerkat.ingestion.es_templates import build_all_ilm_policies, build_all_templates


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    (out_dir / "templates").mkdir(parents=True, exist_ok=True)
    (out_dir / "ilm").mkdir(parents=True, exist_ok=True)

    for name, template in build_all_templates().items():
        (out_dir / "templates" / f"{name}.json").write_text(json.dumps(template, indent=2))

    for name, policy in build_all_ilm_policies().items():
        # ILM 정책 이름은 <name>-ilm 형태로 저장한다
        (out_dir / "ilm" / f"{name}-ilm.json").write_text(json.dumps(policy, indent=2))

    print(f"wrote templates/ilm json under {out_dir}")


if __name__ == "__main__":
    main()
