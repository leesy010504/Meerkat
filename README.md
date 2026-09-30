# Meerkat

**Suricata 룰셋을 지켜보는 에이전트형 보초입니다.** 네트워크 트래픽에서
새로운 공격 패턴을 발견하면 스스로 Suricata 탐지 룰을 만들고, 검증하고,
배포 PR을 올립니다.

## 문제

베어메탈 Kubernetes 클러스터에 Suricata를 IDS로 배치해도 두 가지 한계가
있습니다.

1. 시그니처 기반 룰이 등록되지 않은 신규 패턴은 그냥 지나갑니다.
2. 룰셋을 역할별로 나눠 관리하면, 새 위협마다 "이걸 어느 룰 그룹에 넣을지"
   담당자가 매번 수작업으로 판단해야 합니다.

## 접근

사람이 하던 분석·대응 절차(알럿 클러스터링 → 신규/변종 판단 → 룰 작성 →
문법·트리거·오탐 검증 → 배포)를 도구로 쪼개고, 에이전트가 이 도구들을
스스로 호출해 룰을 생성·수리·배포하도록 만듭니다.

## 시작하기

```bash
# 1. 의존성
brew install uv suricata          # 검증 엔진
uv sync

# 2. 로컬 인프라 (Elasticsearch + 테스트 타겟)
docker compose -f docker-compose.dev.yml up -d

# 3. 환경 변수
cp .env.example .env
# .env에 GEMINI_API_KEY, HF_TOKEN 채우기
#   - Gemini 키: https://aistudio.google.com (무료 티어 있음)
#   - HF 토큰: https://huggingface.co/settings/tokens
#     (+ https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M 접근 승인 필요, gated 모델)

# 4. 테스트
uv run pytest tests/ -v

# 5. (선택) 스케줄러 상시 실행 — ES를 주기적으로 폴링해서 이상 트래픽을
#    감지하면 orchestrate()를 자동으로 부른다. 검증 통과 룰은 settings.deploy.mode에
#    따라 rules/<group>.rules에 반영되고 .meerkat/deploy_proposals/에 제안서가 남는다
uv run python -m meerkat.agent.scheduler
uv run python -m meerkat.agent.scheduler --once --metrics unique_dst_ports_per_src   # 한 주기만

# rules/*.rules를 손으로 고쳤으면 룰 메모리에 반영한다 — 관계 판단과 "이미 커버됨" 선검사가 메모리를 본다
uv run python scripts/sync_rules_to_memory.py

# 6. (선택) 로컬 종단간 데모 — 재현 pcap → Suricata eve → ES → 스케줄러 → 룰 파일.
#    --provider template 은 API 키 없이 결정적 템플릿으로 전체 경로를 돈다
uv run python scripts/demo_local_e2e.py --provider template
uv run python scripts/demo_local_e2e.py                      # 실제 Gemini
```

실제 Gemini 호출 테스트(`tests/test_llm_client.py`)는 무료 티어 일일 한도(모델당 20회)를 쓰기
때문에 기본으로 skip되고, `MEERKAT_RUN_LIVE_LLM=1`을 켠 경우에만 돕니다.

Gemini 키가 여러 개면 `.env`에 `GEMINI_API_KEY`로 시작하는 이름으로 넣어두기만 하면 됩니다
(`GEMINI_API_KEY`, `GEMINI_API_KEY_2` …). 클라이언트가 전부 모아 `GEMINI_API_KEY`부터 쓰고, 한도가
차면 다음 키로, 거부된 키(401/403·잘못된 키)는 그 프로세스에서 다시 쓰지 않습니다. 순서를 직접
정하려면 `GEMINI_API_KEYS=k1,k2`. 로그에는 키 값이 아니라 환경변수 이름만 남습니다.
macOS에서 `tcpdump`로 패킷 캡처를 하려면(공격 시나리오 스크립트용) 한 번
권한을 풀어줘야 합니다:

```bash
sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*
```

## 아키텍처

```
[수집] Suricata eve.json + ingress-nginx 로그 → Filebeat → Elasticsearch

[트리거] 알럿 클러스터링 / 이상 집계(baseline 대비 편차, threshold 후보 산출)
           ↓
[인젝션 필터] 결정적 어휘 규칙(권위 사칭·문맥 조작) → 로컬 분류기 앙상블 (필드별 모델 조합)
           ↓   중첩된 ES 문서(sample_events[].http.url 등)까지 재귀적으로 검사
[관계 판단] 현재 룰셋으로 먼저 매칭 검사(결정적) → 이미 커버되면 LLM 호출 없이 종료
           ↓ 미커버 시
       LLM: 신규 유형인가, 기존 룰의 변종인가?
           ↓ (신규)              ↓ (변종)
      [룰 생성]              [룰 수리]  ← 대표 샘플 + 신규 샘플 둘 다 통과 필수
           ↓________________________↓
[검증 루프] 정책(alert만, sid/rev 고정) → 문법 검사 → 공격 재현(트리거) → 정상 재현(오탐)
           ↓ 실패 시: 결정적 리라이트 → 에러 KB 지침/오탐 플로우 샘플을 넣은 LLM 수리(최대 K회)
[논리 검증 + 역할 그룹 매핑] 룰 내용이 주장하는 위협 분류와 정합하는지 확인
           ↓ 불일치도 바로 실패가 아니라 수리 루프로 되돌림
[배포] rules/<group>.rules 반영 + 제안서(판단 근거·근거 이벤트·검증 과정·배포 가이드)
       → (pr 모드) 브랜치/커밋/PR → 사람 승인 → ArgoCD → suricatasc reload-rules
[감사] 샘플마다 의사결정 로그(JSONL): 관계 판단, 후보 수, 검증 결과, 수리 유형, LLM 호출 수
```

설계상 중요한 세부 결정 몇 가지:

- **룰의 threshold count는 "Suricata가 실제로 세는 양"의 baseline에서 나옵니다.** 이상 탐지는
  고유 포트 수나 4xx 비율로 하지만, `threshold: count N`은 매치된 패킷 수를 세므로 count는
  같은 출발지의 연결 수/요청 수 baseline(p99 × 1.5, 하한 5)에서 따로 뽑습니다
  (`scheduler.METRIC_RULE_COUNT_BASIS`). 고유 포트 p99=4를 count 4로 쓰면 브라우저 하나도 걸립니다.
- **검증은 루프백 캡처에서도 `$EXTERNAL_NET → $HOME_NET` 룰이 매칭되도록** 검증 전용 주소 그룹을
  씁니다(`validation/suricata_env.py`). 룰 텍스트는 바뀌지 않고 운영 suricata.yaml 변수가 그대로
  적용됩니다.
- **LLM 호출 예산**: 샘플 하나당 최대 12회. 신규 생성 경로가 실패하면 관계 판단으로 되돌리지
  않습니다(temperature 0에서는 같은 답이 나와 호출만 태움). 일일 한도 소진(429 + 수 시간 뒤
  재시도)은 일시 에러와 구분해 스케줄러가 알려준 시간만큼 멈춥니다.
- **검증 코퍼스는 역할 그룹별로 나뉩니다.** `pcaps/attack/manifest.yaml`이 pcap을 그룹에 묶고, 룰은
  자기 그룹 pcap에서 울리되 **다른 그룹의 공격 pcap과 정상 pcap에서는 조용해야** 통과합니다
  (`validation/corpus.py`). "아무 공격 pcap에서나 울리면 통과"보다 훨씬 엄격한 기준입니다.
- **rate 룰의 count는 재생으로 보정합니다.** baseline count가 정상 트래픽에 걸리면 LLM을 부르기 전에
  negative pcap이 조용해지는 최소 count를 이분 탐색으로 찾습니다(`validation/threshold_calibrate.py`).
  count는 올리기만 하고, 보정 내역은 감사 로그와 제안서에 남습니다.
- **LLM 없이도 전체 경로가 돕니다** (`llm.provider: template`). 지표별 rate 룰 템플릿에 baseline
  값을 넣는 결정적 구현으로, CI/오프라인 데모/평가 하한 기준선용입니다.

## 디렉토리 구조

```
meerkat/
├── config/                  # settings.yaml(ES/LLM/배포), role_groups.yaml(scanning, web-attack, dns-flood, auth-bruteforce)
├── src/meerkat/
│   ├── mcp_server/          # MCP 도구: ES 쿼리/집계, 문법/리플레이/결정적 리라이트/논리검증, 룰 메모리, 배포, 실패 큐
│   ├── agent/                # 관계판단/생성/수리/선택 + 오케스트레이터 + 스케줄러(자동 폴링) + 의사결정 감사 로그
│   ├── validation/            # 문법검사, 리플레이, 결정적 리라이트(18개), 에러 KB, 논리검증, 검증용 suricata 변수
│   ├── ingestion/             # 알럿 클러스터링, baseline, 라이브 pcap 상관관계, eve.json/nginx 로그 → ES 적재
│   ├── security/               # 인젝션 필터 (어휘 규칙 사전 필터 + 분류기 앙상블)
│   ├── storage/                 # 룰 메모리(대표 샘플 관리), 실패 큐
│   └── llm/                      # LLM 클라이언트 추상화 (gemini/anthropic/template), 할당량 처리
├── scripts/
│   ├── attack_scenarios/         # nmap/gobuster/hydra/dig 재현 + pcap 캡처
│   ├── capture_benign_traffic.py # 정상 트래픽 재현 + pcap 캡처 (오탐 검사 코퍼스)
│   ├── demo_local_e2e.py         # 로컬 종단간 데모
│   ├── ingest_pcap_to_es.py / ingest_nginx_access.py  # pcap·access log → ES (Filebeat 대체, 로컬용)
│   ├── import_community_rules.py # ET Open 등 외부 룰셋 임포트
│   ├── sync_rules_to_memory.py   # rules/*.rules → 룰 메모리(origin=manual)
│   ├── render_rules_configmap.py # rules/ → deploy/k8s ConfigMap
│   ├── rule_alert_report.py      # 배포 룰 sid별 알럿량 리포트 (사후 모니터링, 읽기 전용)
│   └── benchmark_injection_filter.py / generate_synthetic_injection_data.py
├── eval/                          # 지표(SA/SS/SE/ADR/RC/RUR/DL), ablation(검증 단계별), injection_sway(SR/ISR)
├── pcaps/{attack,benign}/         # 검증용 트래픽 캡처
├── rules/                          # 배포 대상 룰셋 (GitOps 소스) — scanning / web-attack / auth-bruteforce / dns-flood
├── deploy/k8s/                     # Suricata DaemonSet, ES, Filebeat, 룰 ConfigMap
├── .github/workflows/ci.yml        # ruff + pytest (Suricata 8 설치 포함)
└── tests/
```

## 평가

```bash
# 검증 단계별 ablation (none / syntax / syntax_attack / full) — 스펙 §11의 핵심 실험
uv run python -m eval.ablation --provider template                 # 키 없이
uv run python -m eval.ablation --provider gemini --conditions none,full --model gemini-3.6-flash
uv run python -m eval.ablation --provider template --scenarios hard   # 저속 스캔·UA 위장 탐색 (all = 6개 전부)

# 인젹션 필터 필드별 FPR/TPR
uv run python scripts/benchmark_injection_filter.py

# 인젹션이 관계 판단을 흔드는 정도 (SR/ISR) — 실제 LLM 필요
uv run python -m eval.injection_sway --samples 6

# 매핑 원칙(검색 필드만 색인, 보관 필드 index:false, best_compression)의 인덱스 크기 절감률
uv run python scripts/measure_index_savings.py pcaps/attack/port_scan.pcap   # 실측: 매핑만 47%, +화이트리스트 59%
```

결과는 `eval/results/`에 쌓이고, 스케줄러의 판단 기록은 `.meerkat/audit/decisions.jsonl`에 남습니다.

현재 실측(시나리오 4개, 실제 Gemini): 검증 없이 SE는 소형 모델 0.625, 대형 모델 0.750이고, 전체 검증
루프를 켜면 둘 다 1.000으로 격차가 사라집니다. 소형 모델이 치르는 비용은 LLM 호출 1회 더입니다.
배포 룰을 피해 가는 어려운 시나리오(저속 스캔, 브라우저 UA로 위장한 디렉토리 탐색)에서는 검증 없이
저속 스캔을 제대로 잡은 모델이 없었고(대형 포함), 전체 검증은 오탐 룰을 하나도 내보내지 않았습니다.
저속 스캔은 재생 기반 임계값 분리 탐색(창 60→300초)을 넣은 뒤 소형 모델에서도 매번 통과했습니다.
자세한 표와 한계는 `docs/PROGRESS.md` 8.3절.
