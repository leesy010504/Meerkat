"""rules/*.rules를 모아 deploy/k8s/20-suricata-rules-configmap.yaml을 다시 만든다.

ConfigMap을 손으로 고치면 rules/ 디렉토리(GitOps 소스)와 어긋난다 — ArgoCD가 없는 로컬에서
같은 결과물을 만들어보는 용도. 실제 배포에서는 ArgoCD가 rules/를 ConfigMap으로 동기화한다.
"""

import argparse
from pathlib import Path

HEADER = """# 이 파일은 scripts/render_rules_configmap.py가 rules/*.rules에서 생성한다. 직접 편집하지 말 것.
apiVersion: v1
kind: ConfigMap
metadata:
  name: suricata-rules
  namespace: meerkat
data:
"""


def render(rules_dir: Path) -> str:
    """DaemonSet이 `-S /rules/local.rules` 하나만 읽으므로 그룹 파일을 한 키로 합친다."""
    out = HEADER + "  local.rules: |\n"
    for path in sorted(rules_dir.glob("*.rules")):
        out += f"    # --- {path.name} ---\n"
        for line in path.read_text().splitlines():
            if line.strip():
                out += f"    {line.rstrip()}\n"
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-dir", default="rules")
    parser.add_argument("--output", default="deploy/k8s/20-suricata-rules-configmap.yaml")
    args = parser.parse_args()
    Path(args.output).write_text(render(Path(args.rules_dir)))
    print(f"wrote {args.output}")
