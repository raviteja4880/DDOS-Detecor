import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import pytest

from ddos_detector.config import Config, load_config, validate_config


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


def test_validate_config_rejects_invalid_values():
    with pytest.raises(ValueError):
        validate_config(Config(interface="", window_seconds=5, slide_seconds=1))

    with pytest.raises(ValueError):
        validate_config(Config(interface="lo", window_seconds=0, slide_seconds=1))

    with pytest.raises(ValueError):
        validate_config(Config(interface="lo", window_seconds=5, slide_seconds=7))

    with pytest.raises(ValueError):
        validate_config(Config(interface="lo", window_seconds=5, slide_seconds=1, capture={"snaplen": 0}))
