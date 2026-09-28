"""로컬 종단간 데모: 재현 트래픽 → Suricata eve → ES → 스케줄러 → 오케스트레이터(실제 LLM) → 룰 파일.

운영 환경(k8s + Filebeat + ArgoCD) 없이, 로컬 docker-compose ES 하나로 파이프라인 전체가
실제로 룰을 만들어내는지 확인한다. 실제 Gemini를 호출한다 (GEMINI_API_KEY 필요).

    uv run python scripts/demo_local_e2e.py            # 전체 실행
    uv run python scripts/demo_local_e2e.py --keep     # ES 데모 인덱스를 지우지 않고 시작

산출물은 전부 .meerkat/demo/ 아래에 쓴다 (rule_memory 복사본, rules/, proposals/, audit.jsonl).
실제 rules/ 디렉토리와 .meerkat/rule_memory.json은 건드리지 않는다.
"""

import argparse
import asyncio
import datetime
import json
import logging
import shutil
import subprocess
from pathlib import Path

from elasticsearch import AsyncElasticsearch

from meerkat.agent.scheduler import (
    SchedulerConfig,
    SchedulerState,
    build_from_settings,
    poll_once,
)
from meerkat.config import load_settings
from meerkat.ingestion.es_templates import build_all_templates
from meerkat.ingestion.eve_ingest import (
    bulk_index_documents,
    eve_to_document,
    nginx_lines_to_documents,
    run_suricata_to_eve,
    shift_timestamps_to_now,
)
from meerkat.storage.failure_queue import FailureQueue
from meerkat.storage.rule_memory import RuleMemory

DEMO_DIR = Path(".meerkat/demo")
DEMO_INDICES = "suricata-*,nginx-access-*"
BASELINE_DAYS = 10


async def reset_indices(client: AsyncElasticsearch) -> None:
    # ES 기본 설정(destructive_requires_name)은 와일드카드 삭제를 막는다 — 이름을 풀어서 지운다
    existing = await client.indices.get(index=DEMO_INDICES, ignore_unavailable=True)
    if existing:
        await client.indices.delete(index=",".join(existing.keys()))
    for name, template in build_all_templates().items():
        await client.indices.put_index_template(
            name=f"meerkat-{name}", index_patterns=template["index_patterns"], template=template["template"]
        )


async def seed_baseline(client: AsyncElasticsearch, now: datetime.datetime) -> int:
    """평시 분포를 만든다 — 지표마다 MIN_BASELINE_SAMPLES(20) 이상의 (윈도우, src) 표본이 필요하다."""
    docs = []
    for day in range(1, BASELINE_DAYS + 1):
        for hour in (3, 9, 15, 21):
            ts = now - datetime.timedelta(days=day, hours=hour)
            for i in range(3):
                src = f"10.20.{day}.{10 + i}"
                # 평시 클라이언트: 5분에 고유 포트 1~4개, 연결(flow) 8~40개 — 브라우저가 한 호스트에
                # 여러 연결을 여는 걸 반영한다. 연결 수 baseline이 룰 count의 기준이 된다.
                unique_ports = 1 + ((day + i) % 4)
                conns = 8 + ((day * 7 + i * 11) % 33)
                for c in range(conns):
                    port = 8000 + (c % unique_ports)
                    docs.append(("suricata-flow", {
                        "@timestamp": (ts + datetime.timedelta(seconds=c * 3)).isoformat(), "src_ip": src,
                        "dest_ip": "10.0.0.1", "src_port": 40000 + c, "dest_port": port, "proto": "TCP",
                        "event_type": "flow",
                        "flow": {"pkts_toserver": 6, "pkts_toclient": 5, "state": "closed", "age": 1},
                    }))
                # 평시 웹 사용: 5분에 엔드포인트 2~4개, 요청 6~30개, 전부 200
                endpoints = 2 + ((day + i) % 3)
                requests = 6 + ((day * 5 + i * 13) % 25)
                for j in range(requests):
                    docs.append(("nginx-access", {
                        "@timestamp": (ts + datetime.timedelta(seconds=j * 5)).isoformat(), "src_ip": src,
                        "event_type": "nginx-access",
                        "nginx": {"path": f"/page{j % endpoints}", "status": 200, "method": "GET",
                                  "user_agent": "Mozilla/5.0"},
                    }))
    counts = await bulk_index_documents(client, docs)
    return sum(counts.values())


def run_dir_bruteforce_against_local_target(scratch: Path) -> list[str]:
    """gobuster를 로컬 nginx 타겟에 실제로 돌리고 그 access log 줄을 가져온다 (pcap은 scratch에)."""
    subprocess.run(
        ["gobuster", "dir", "-u", "http://localhost:8080", "-w", "tests/fixtures/wordlist.txt", "-q",
         "-o", str(scratch / "gobuster.txt")],
        capture_output=True, text=True, check=False,
    )
    logs = subprocess.run(["docker", "logs", "--since", "2m", "meerkat-target-nginx-1"],
                          capture_output=True, text=True, check=False)
    return [line for line in (logs.stdout + logs.stderr).splitlines() if "gobuster" in line]


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true", help="시작할 때 기존 데모 인덱스를 지우지 않는다")
    parser.add_argument("--keep-indices", action="store_true",
                        help="끝나고 ES 데모 인덱스를 남긴다 (기본은 삭제 — 로컬 ES를 쓰는 통합테스트와 섞이지 않게)")
    parser.add_argument("--skip-web", action="store_true", help="gobuster 재현을 건너뛴다")
    parser.add_argument("--metrics", default="unique_dst_ports_per_src,failed_conn_ratio_per_src,"
                                             "conn_count_per_src_port,unique_endpoints_per_src,http_4xx_ratio_per_src")
    parser.add_argument("--provider", default=None, choices=["gemini", "anthropic", "template"],
                        help="settings.llm.provider 대신 쓸 LLM 프로바이더 (template = 키 없이 결정적 템플릿)")
    parser.add_argument("--model", default=None, help="모든 역할에 이 모델을 쓴다 (settings 대신)")
    parser.add_argument("--exclude-manual", action="store_true",
                        help="데모용 rule_memory 복사본에서 origin=manual(rules/에 손으로 넣은 룰)을 뺀다 — "
                             "이미 커버된 시나리오에서 LLM 생성 경로를 보고 싶을 때")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("elastic_transport").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    settings = load_settings()
    if args.provider:
        settings = settings.model_copy(update={"llm": settings.llm.model_copy(update={"provider": args.provider})})
    if args.model:
        settings = settings.model_copy(update={"llm": settings.llm.model_copy(update={
            "model_relation_assess": args.model, "model_rule_generate": args.model,
            "model_rule_repair": args.model, "model_sample_select": args.model})})
    es_client, llm_client, _, models, verify_ctx, _ = build_from_settings(settings)
    print(f"[0] llm provider = {settings.llm.provider}, model = {settings.llm.model_rule_generate}")

    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR)
    DEMO_DIR.mkdir(parents=True)
    # 실제 rule_memory(ET Open 임포트 8천여 개 포함)를 복사해 쓴다 — 선검사에 참여시키되 원본은 보존
    shutil.copy(".meerkat/rule_memory.json", DEMO_DIR / "rule_memory.json")
    if args.exclude_manual:
        data = json.loads((DEMO_DIR / "rule_memory.json").read_text())
        kept = {k: v for k, v in data.items() if v.get("origin") != "manual"}
        (DEMO_DIR / "rule_memory.json").write_text(json.dumps(kept))
        print(f"[0] excluded {len(data) - len(kept)} manual rule(s) from demo memory")
    rule_memory = RuleMemory(path=DEMO_DIR / "rule_memory.json")
    failure_queue = FailureQueue(path=DEMO_DIR / "failure_queue.json")

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        if not args.keep:
            await reset_indices(es_client)
            n = await seed_baseline(es_client, now)
            print(f"[1] baseline seeded: {n} docs over {BASELINE_DAYS} days")

        # [2] 공격 재현 트래픽 적재 (캡처 시각을 지금으로 평행이동)
        for pcap in ("pcaps/attack/port_scan.pcap", "pcaps/attack/auth_bruteforce.pcap"):
            events = run_suricata_to_eve(pcap, settings.suricata.binary)
            docs = shift_timestamps_to_now([d for d in map(eve_to_document, events) if d is not None], now=now)
            counts = await bulk_index_documents(es_client, docs)
            print(f"[2] {pcap}: {sum(counts.values())} docs -> {sorted(counts)}")

        if not args.skip_web:
            lines = run_dir_bruteforce_against_local_target(DEMO_DIR)
            docs = shift_timestamps_to_now(list(nginx_lines_to_documents(lines)), now=now)
            counts = await bulk_index_documents(es_client, docs)
            print(f"[2] gobuster vs local nginx: {len(lines)} access-log lines -> {sum(counts.values())} docs")

        # [3] 스케줄러 한 주기 — 실제 LLM
        config = SchedulerConfig(
            window_seconds=300,
            metrics=tuple(m.strip() for m in args.metrics.split(",") if m.strip()),
            deploy_mode="file",
            rules_dir=str(DEMO_DIR / "rules"),
            proposals_dir=str(DEMO_DIR / "proposals"),
            audit_log_path=str(DEMO_DIR / "audit.jsonl"),
            pcaps_attack_dir=settings.paths.pcaps_attack,
            pcaps_benign_dir=settings.paths.pcaps_benign,
        )
        deployed = await poll_once(
            es_client, llm_client, rule_memory, models, verify_ctx, failure_queue, config, state=SchedulerState()
        )
    finally:
        if not args.keep_indices:
            existing = await es_client.indices.get(index=DEMO_INDICES, ignore_unavailable=True)
            if existing:
                await es_client.indices.delete(index=",".join(existing.keys()))
                print(f"[cleanup] deleted demo indices: {sorted(existing)}")
        await es_client.close()

    # [4] 결과
    print(f"\n[3] deployed {len(deployed)} rule(s):")
    for item in deployed:
        print(f"  sid={item.sid} rev={item.rev} group={item.role_group}\n    {item.rule_text}")
    failures = await failure_queue.list()
    print(f"[3] failure queue: {len(failures)}")
    for f in failures:
        print(f"  metric={f.metric} src_ip={f.src_ip} proposed={f.proposed_category} reason={f.reason[:160]}")

    audit_path = DEMO_DIR / "audit.jsonl"
    if audit_path.exists():
        print("\n[4] decision audit:")
        for line in audit_path.read_text().splitlines():
            rec = json.loads(line)
            ctx = rec["context"]
            print(f"  {ctx['metric']} src={ctx['src_ip']} value={ctx['observed_value']} thr={ctx['suggested_threshold']}"
                  f" -> {rec['outcome']} (llm_calls={rec['llm_calls']}, verify_runs={rec['verify_runs']}, repairs={rec['repairs']})")
    for p in sorted((DEMO_DIR / "proposals").glob("*.md")) if (DEMO_DIR / "proposals").exists() else []:
        print(f"  proposal: {p}")


if __name__ == "__main__":
    asyncio.run(main())
