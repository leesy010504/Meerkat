# Meerkat

**Suricata 룰셋을 지켜보는 에이전트형 보초.** 네트워크 트래픽에서 새로운
공격 패턴을 발견하면 스스로 Suricata 탐지 룰을 만들고, 검증하고, 배포
PR을 올린다.

> 미어캣 무리에서는 한 마리가 뒷다리로 서서 주변을 감시하다 위협을
> 발견하면 경보를 낸다. Meerkat은 Suricata(학명 *Suricata suricatta*,
> 미어캣) 룰셋을 지켜보는 그 역할을 한다. Suricata의 포크나 대체재가
> 아니라 그 위에서 동작하는 별개 도구다.

## 문제

베어메탈 Kubernetes 클러스터에 Suricata를 IDS로 배치해도 두 가지 한계가
있다.

1. 시그니처 기반 룰이 등록되지 않은 신규 패턴은 그냥 지나간다.
2. 룰셋을 역할별로 나눠 관리하면, 새 위협마다 "이걸 어느 룰 그룹에 넣을지"
   담당자가 매번 수작업으로 판단해야 한다.

## 접근

사람이 하던 분석·대응 절차(알럿 클러스터링 → 신규/변종 판단 → 룰 작성 →
문법·트리거·오탐 검증 → 배포)를 도구로 쪼개고, 에이전트가 이 도구들을
스스로 호출해 룰을 생성·수리·배포하도록 만든다.

### 이 프로젝트의 차별점

기존 연구(RulePilot, GRIDAI, GenTI)는 단발성 페이로드 매칭 룰만 다루거나,
`threshold`/`detection_filter` 같은 rate-based 룰을 쓰려면 분석가가 시간
임계값을 직접 프롬프트로 지정해야 했다.

Meerkat은 Elasticsearch 시계열 집계로 **평시 baseline 분포(p50/p95/p99)에서
임계값을 자동으로 도출**해서, 사람 개입 없이 stateful 탐지 룰까지 만든다.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
  msg:"LOCAL Port Scan - Multiple Ports from Single Source";
  flow:to_server;
  threshold:type threshold, track by_src, count 70, seconds 60;  # ← baseline에서 자동 도출
  classtype:attempted-recon; sid:1000001; rev:1;
)
```

## 설계 원칙

- **LLM은 최후에 호출한다.** 클러스터링, 룰셋 매칭, 문법 검사, 17개 결정적
  리라이트 같은 건 전부 코드로 처리한다. LLM은 "신규 vs 변종 판단"과
  "룰 생성/수리"에만 쓴다.
- **로그는 적대적 입력이다.** `http.user_agent`, `http.uri` 같은 필드는
  공격자가 내용을 통제할 수 있다. 모든 LLM 출력은 JSON 스키마로 강제하고,
  사람이 읽는 설명 필드(`reasoning` 등)는 절대 다음 단계 입력으로 재사용하지
  않는다. 로그 필드는 인젝션 필터(로컬 분류기 앙상블)를 거친 뒤에야 LLM에
  전달된다.
- **새 룰을 만들기 전에 정말 필요한지 판단한다.** 신규 알럿마다 룰을
  새로 만들면 룰셋이 무한 팽창한다. 관계 판단 단계가 이걸 막는다.
- **검증은 실행 기반으로 한다.** 문법 검사만으로는 부족하다. 실제 공격
  트래픽 재현(트리거 확인)과 정상 트래픽 재현(오탐 확인)을 둘 다 통과해야
  배포 후보가 된다.
- **Suricata는 IDS 전용이다.** 생성 룰의 액션은 항상 `alert`. `drop`/`reject`는
  절대 만들지 않는다. 실제 차단이 필요하면 별도 CiliumNetworkPolicy를
  사람이 승인해서 배포한다.
- **에이전트는 배포 권한이 없다.** 룰 파일을 고친 브랜치를 만들고 PR을
  여는 데까지만 한다. 실제 클러스터 반영은 사람이 PR을 승인해야 일어난다.
  룰 삭제·비활성화 권한도 없다.

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

## 기술 스택

| 영역 | 선택 |
|---|---|
| 언어 / 패키지 관리 | Python 3.11+, `uv` |
| MCP 서버 | MCP Python SDK |
| ES 클라이언트 | `elasticsearch-py` (async, 8.x) |
| 인젝션 필터 | Llama Prompt Guard 2 (86M) + protectai/deberta-v3-prompt-injection-v2 앙상블, 필드별 라우팅 |
| LLM | Gemini API (`typing.Protocol` 기반이라 Anthropic 등으로 교체 가능) |
| 검증 엔진 | Suricata 8.x |
| 테스트 | pytest, pytest-asyncio |

파인튜닝, 벡터DB/RAG, 로컬 LLM은 의도적으로 안 쓴다.

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
권한을 풀어줘야 한다:

```bash
sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*
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

## 현재 상태
Phase 1 범위 대부분을 실제 인프라(진짜 Suricata, 진짜 Elasticsearch, 진짜
pcap 캡처, 진짜 Gemini API 호출)로 검증했다.

GitOps PR 자동화는 아직 실제 저장소로 검증하지 않았고, 인젝션 필터는
필드별로 탐지 성능 편차가 있다(URI는 강하고, User-Agent/도메인류 필드는 약함).

`scripts/import_community_rules.py`로 ET Open 같은 외부 커뮤니티 룰셋을
`origin="imported"`로 가져올 수 있다 — "우리가 처음부터 다 만들 필요 없다,
이미 분석된 CVE 시그니처는 가져다 쓰면 된다"는 취지. `suricata-update`로
받은 ET Open 52,713개 중 우리 스코프(scanning/web-attack)에 맞는 8,301개를
실제로 임포트해서 검증했다. imported 룰은 결정적 매칭 검사에는 참여하지만
LLM 프롬프트에는 안 들어간다.

스케줄러(`agent/scheduler.py`)가 ES를 폴링해 이상 트래픽을 감지하고
`orchestrate()`를 자동 호출하는 것, 그리고 특정 알럿의 5-tuple로 Suricata
pcap-log 회전 파일에서 그 플로우 패킷만 뽑아 검증용 증거로 넘기는 것
(`ingestion/pcap_capture.py`)까지 실제 ES + 실제 suricata + 실제 pcap으로
확인했다. 다만 이건 정적 pcap을 "회전 파일인 척" 두고 검증한 거고, 실제
라이브 인터페이스에 `pcap-log`를 켜서 돌려본 적은 없다.