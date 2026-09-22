from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel


class ElasticsearchConfig(BaseModel):
    hosts: list[str]
    read_only_user: str

class LLMConfig(BaseModel):
    provider: str
    model_relation_assess: str  # 대형 모델
    model_rule_generate: str  # 중형 모델
    model_rule_repair: str  # 중형 모델
    model_sample_select: str  # 소형 모델
    temperature: float = 0.0

class RetryConfig(BaseModel):
    max_repair_attempts: int = 3

class SuricataConfig(BaseModel):
    binary: str = "suricata"
    container_image: str | None = None
    rule_sid_range: tuple[int, int]

class PathsConfig(BaseModel):
    pcaps_attack: str
    pcaps_benign: str
    rules_dir: str
    pcap_log_dir: str | None = None  # Suricata pcap-log 회전 파일 위치, 라이브 캡처용

class DeployConfig(BaseModel):
    # none: rule_memory에만 기록 / file: rules/<group>.rules + 제안서 작성 / pr: file + 브랜치·커밋·gh pr
    mode: Literal["none", "file", "pr"] = "file"
    repo_dir: str = "."  # pr 모드에서 룰 레포 체크아웃 위치 (이 레포가 아니라 GitOps 룰 레포여야 한다)
    proposals_dir: str = ".meerkat/deploy_proposals"
    audit_log_path: str | None = ".meerkat/audit/decisions.jsonl"  # 의사결정 감사 로그(JSONL)


class Settings(BaseModel):
    elasticsearch: ElasticsearchConfig
    llm: LLMConfig
    retry: RetryConfig
    suricata: SuricataConfig
    paths: PathsConfig
    deploy: DeployConfig = DeployConfig()

def load_dotenv_if_present() -> None:
    """레포 루트의 .env(GEMINI_API_KEY, HF_TOKEN, MEERKAT_ES_PASSWORD)를 환경변수로 올린다.

    테스트는 conftest에서 하지만 스케줄러/스크립트 엔트리포인트는 그동안 아무도 안 해서
    `python -m meerkat.agent.scheduler`가 키 없음으로 바로 죽었다. 이미 설정된 변수는 덮지 않는다.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover
        return
    load_dotenv(override=False)


def load_settings(path: str | Path = "config/settings.yaml") -> Settings:
    load_dotenv_if_present()
    raw = yaml.safe_load(Path(path).read_text())
    return Settings.model_validate(raw)
