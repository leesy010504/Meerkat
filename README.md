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
#    감지하면 orchestrate()를 자동으로 부른다
uv run python -m meerkat.agent.scheduler
```
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
[인젝션 필터] 로컬 분류기 앙상블 (필드별로 다른 모델 조합)
           ↓
[관계 판단] 현재 룰셋으로 먼저 매칭 검사(결정적) → 이미 커버되면 LLM 호출 없이 종료
           ↓ 미커버 시
       LLM: 신규 유형인가, 기존 룰의 변종인가?
           ↓ (신규)              ↓ (변종)
      [룰 생성]              [룰 수리]  ← 대표 샘플 + 신규 샘플 둘 다 통과 필수
           ↓________________________↓
[검증 루프] 문법 검사 → 공격 재현(트리거 확인) → 정상 재현(오탐 확인)
           ↓ 실패 시: 결정적 리라이트 → LLM 수리(최대 K회) → 그래도 실패면 신규 생성 강제
[논리 검증 + 역할 그룹 매핑] 룰 내용이 주장하는 위협 분류와 정합하는지 확인
           ↓
[배포] GitOps PR 생성 (판단 근거 + 근거 이벤트 + 배포 가이드 포함) → 사람 승인 → ArgoCD
```

## 디렉토리 구조

```
meerkat/
├── config/                  # settings.yaml, role_groups.yaml
├── src/meerkat/
│   ├── mcp_server/          # MCP 도구: ES 쿼리/집계, 룰 검증, 배포
│   ├── agent/                # 관계판단/생성/수리/선택 + 오케스트레이터 + 스케줄러(자동 폴링)
│   ├── validation/            # 문법검사, 리플레이, 결정적 리라이트, 논리검증
│   ├── ingestion/             # 알럿 클러스터링, baseline 산출, 라이브 pcap 상관관계
│   ├── security/               # 인젝션 필터
│   ├── storage/                 # 룰 메모리(대표 샘플 관리)
│   └── llm/                      # LLM 클라이언트 추상화
├── scripts/attack_scenarios/     # nmap/gobuster/hydra 재현 스크립트
├── scripts/import_community_rules.py  # ET Open 등 외부 룰셋 임포트
├── eval/                          # 평가 지표(SA/SS/SE/ADR/RC/RUR/DL)
├── pcaps/{attack,benign}/         # 검증용 트래픽 캡처
├── rules/                          # 배포 대상 룰셋 (GitOps 소스)
└── tests/
```
