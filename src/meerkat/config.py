from pathlib import Path
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

class Settings(BaseModel):
    elasticsearch: ElasticsearchConfig
    llm: LLMConfig
    retry: RetryConfig
    suricata: SuricataConfig
    paths: PathsConfig

def load_settings(path: str | Path = "config/settings.yaml") -> Settings:
    raw = yaml.safe_load(Path(path).read_text())
    return Settings.model_validate(raw)