"""k8s 매니페스트가 코드(템플릿/적재/룰 파일)와 어긋나지 않는지 확인한다."""

from pathlib import Path

import yaml

from meerkat.ingestion.es_templates import INDEX_RETENTION_DAYS
from meerkat.ingestion.eve_ingest import EVE_INDEX_PREFIX


def test_filebeat_keeps_exactly_the_event_types_that_have_templates():
    doc = yaml.safe_load(Path("deploy/k8s/21-filebeat-configmap.yaml").read_text())
    fb = yaml.safe_load(doc["data"]["filebeat.yml"])
    suricata_input = next(i for i in fb["filebeat.inputs"] if i.get("fields", {}).get("log_kind") == "suricata")
    keep = {c["equals"]["event_type"] for c in suricata_input["processors"][0]["drop_event"]["when"]["not"]["or"]}
    assert keep == set(EVE_INDEX_PREFIX)  # eve_ingest.py와 동일한 타입 집합
    assert {f"suricata-{t}" for t in keep} <= set(INDEX_RETENTION_DAYS)

    # 인덱스 이름이 템플릿 패턴(suricata-<type>-*, nginx-access-*)에 걸리는 모양이어야 한다
    indices = fb["output.elasticsearch"]["indices"]
    assert indices[0]["index"].startswith("nginx-access-")
    assert indices[1]["index"].startswith("suricata-%{[event_type]}-")
    assert fb["setup.template.enabled"] is False  # 템플릿은 apply_es_templates.py가 관리


def test_rules_configmap_matches_rules_dir():
    doc = yaml.safe_load(Path("deploy/k8s/20-suricata-rules-configmap.yaml").read_text())
    rendered = [line for line in doc["data"]["local.rules"].splitlines() if line.strip() and not line.startswith("#")]
    on_disk = [line.strip() for p in sorted(Path("rules").glob("*.rules")) for line in p.read_text().splitlines()
               if line.strip() and not line.startswith("#")]
    assert rendered == on_disk, "run scripts/render_rules_configmap.py"


def test_daemonset_loads_the_rendered_rules_file():
    ds = yaml.safe_load(Path("deploy/k8s/22-suricata-daemonset.yaml").read_text())
    container = ds["spec"]["template"]["spec"]["containers"][0]
    assert "/rules/local.rules" in container["args"]
