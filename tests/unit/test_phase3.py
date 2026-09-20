import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import pytest

from ddos_detector.alerts import maybe_emit_alert
from ddos_detector.main import main
from ddos_detector.mitigation import MitigationManager
from ddos_detector.recovery import RecoveryTracker
from ddos_detector.simulator import simulate_window, validate_simulation_config


def test_simulation_rejects_public_targets():
    with pytest.raises(ValueError):
        validate_simulation_config({"target": "8.8.8.8"})

    cfg = validate_simulation_config({
        "target": "10.0.0.5",
        "mode": "distributed",
        "rate_limit": 1000,
        "packet_limit": 50000,
        "max_sources": 25,
    })
    assert cfg.target == "10.0.0.5"
    metric = simulate_window("distributed", cfg)
    assert metric.unique_src_ips >= 20


def test_alert_and_recovery_flow():
    alert = maybe_emit_alert(
        "SUSPICIOUS",
        0.81,
        ["distributed source spike"],
        current_metrics={"packets_per_sec": 1300},
        baseline={"packets_per_sec": 180},
    )
    assert alert is not None
    assert alert["classification"] == "SUSPICIOUS"

    tracker = RecoveryTracker()
    record = tracker.record_alert("alert-1", "127.0.0.1", "initial observation")
    assert record.status == "monitoring"
    assert tracker.close_alert("alert-1", "traffic returned to baseline").status == "cleared"
    assert tracker.list_active() == []


def test_dry_run_mitigation_is_disabled_by_default():
    manager = MitigationManager({
        "enabled": False,
        "dry_run": True,
        "mechanism": "nftables",
        "rule_ttl_seconds": 60,
    })
    result = manager.apply("127.0.0.1", "lo", "test")
    assert result["dry_run"] is True
    assert "Mitigation disabled" in result["message"]
    assert not manager.rules


def test_cli_simulate_command(capsys):
    result = main(["simulate", "--mode", "distributed"])
    captured = capsys.readouterr().out
    assert result == 0
    assert "Simulation mode=distributed" in captured
