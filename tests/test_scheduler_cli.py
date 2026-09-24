"""스케줄러 CLI 인자 → SchedulerConfig 매핑."""

import argparse

from meerkat.agent.scheduler import METRIC_CONFIG, _build_scheduler_config
from meerkat.config import load_settings


def _args(**overrides):
    base = dict(poll_interval=None, window=None, metrics=None)
    base.update(overrides)
    return argparse.Namespace(**base)


def test_defaults_come_from_settings_and_dataclass():
    settings = load_settings()
    config = _build_scheduler_config(settings, _args())
    assert config.metrics == tuple(METRIC_CONFIG.keys())
    assert config.poll_interval_seconds == 300 and config.window_seconds == 300
    assert config.deploy_mode == settings.deploy.mode
    assert config.rules_dir == settings.paths.rules_dir
    assert config.audit_log_path == settings.deploy.audit_log_path


def test_cli_overrides_are_applied():
    settings = load_settings()
    config = _build_scheduler_config(settings, _args(poll_interval=60, window=120, metrics="dns_query_rate_per_src, unique_dst_ports_per_src"))
    assert config.poll_interval_seconds == 60 and config.window_seconds == 120
    assert config.metrics == ("dns_query_rate_per_src", "unique_dst_ports_per_src")
