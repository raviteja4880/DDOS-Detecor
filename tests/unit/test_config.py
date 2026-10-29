import sys
import pathlib
import os

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import pytest

from ddos_detector.config import Config, load_config, validate_config
from ddos_detector.mitigation import MitigationConfig, MitigationManager


def test_mitigation_defaults_are_safe_and_consistent():
    assert Config().mitigation["enabled"] is False
    assert Config().mitigation["dry_run"] is True
    assert MitigationConfig().enabled is False
    assert MitigationConfig().dry_run is True
    assert MitigationManager().config.enabled is False
    assert MitigationManager().config.dry_run is True

    cfg = load_config(str(ROOT / "config" / "config.yaml"))
    assert cfg.mitigation["enabled"] is False
    assert cfg.mitigation["dry_run"] is True
    assert cfg.mitigation["auto_block_sources"] is False


def test_explicit_lab_configuration_can_enable_live_mitigation():
    cfg = validate_config(Config(mitigation={"enabled": True, "dry_run": False}))
    assert cfg.mitigation["enabled"] is True
    assert cfg.mitigation["dry_run"] is False


def test_load_config_reads_values(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
interface: eth0
window_seconds: 7
slide_seconds: 2
capture:
  bpf_filter: "tcp"
  snaplen: 4096
logging:
  level: DEBUG
  json: true
""".strip(),
        encoding="utf-8",
    )
    cfg = load_config(str(config_file))
    assert cfg.interface == "eth0"
    assert cfg.window_seconds == 7
    assert cfg.slide_seconds == 2
    assert cfg.capture["bpf_filter"] == "tcp"
    assert cfg.capture["snaplen"] == 4096
    assert cfg.logging["level"] == "DEBUG"
    assert cfg.logging["json"] is True


def test_load_config_rejects_non_mapping_yaml(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("- not\n- a mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="configuration root must be a mapping"):
        load_config(str(config_file))


def test_validate_config_rejects_invalid_values():
    with pytest.raises(ValueError):
        validate_config(Config(interface="", window_seconds=5, slide_seconds=1))

    with pytest.raises(ValueError):
        validate_config(Config(interface="lo", window_seconds=0, slide_seconds=1))

    with pytest.raises(ValueError):
        validate_config(Config(interface="lo", window_seconds=5, slide_seconds=7))

    with pytest.raises(ValueError):
        validate_config(Config(interface="lo", window_seconds=5, slide_seconds=1, capture={"snaplen": 0}))


def test_email_disabled_allows_missing_brevo_environment(monkeypatch):
    for name in ("BREVO_API_KEY", "BREVO_SENDER_EMAIL", "BREVO_SENDER_NAME", "BREVO_ALERT_RECIPIENT"):
        monkeypatch.delenv(name, raising=False)
    cfg = Config(alerts={"enabled": True, "email": {"enabled": False}})
    assert validate_config(cfg) is cfg


def test_email_enabled_without_brevo_environment_is_non_fatal_and_diagnostic(monkeypatch, caplog):
    for name in ("BREVO_API_KEY", "BREVO_SENDER_EMAIL", "BREVO_SENDER_NAME", "BREVO_ALERT_RECIPIENT"):
        monkeypatch.delenv(name, raising=False)
    assert validate_config(Config(alerts={"enabled": True, "email": {"enabled": True}}))
    assert "EMAIL_CONFIGURATION_VALID=false" in caplog.text


def test_project_local_env_is_loaded_without_overriding_process(monkeypatch, tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config.yaml"
    config_path.write_text("alerts:\n  email:\n    enabled: false\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "BREVO_API_KEY=local-key\nBREVO_SENDER_EMAIL=sender@example.com\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("BREVO_API_KEY", raising=False)
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "process@example.com")
    from ddos_detector.environment import load_project_environment
    load_project_environment(str(config_path))
    assert os.environ["BREVO_API_KEY"] == "local-key"
    assert os.environ["BREVO_SENDER_EMAIL"] == "process@example.com"
