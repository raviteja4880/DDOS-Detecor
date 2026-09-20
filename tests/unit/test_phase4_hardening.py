import io
import json
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import pytest

from ddos_detector.config import Config, validate_config
from ddos_detector.main import build_parser, main
from ddos_detector.mitigation import MitigationManager, MitigationRule


def test_validate_config_rejects_invalid_thresholds():
    with pytest.raises(ValueError):
        validate_config(Config(thresholds={"normal": 0.8, "suspicious": 0.6}))

    with pytest.raises(ValueError):
        validate_config(Config(simulation={"target": "8.8.8.8"}))


def test_validate_config_rejects_unsafe_bounds():
    with pytest.raises(ValueError):
        validate_config(Config(simulation={"rate_limit": 25000}))

    with pytest.raises(ValueError):
        validate_config(Config(simulation={"packet_limit": 600000}))

    with pytest.raises(ValueError):
        validate_config(Config(simulation={"max_sources": 1000}))


def test_mitigation_rejects_invalid_mechanism():
    with pytest.raises(ValueError):
        MitigationManager({"enabled": True, "dry_run": True, "mechanism": "iptables"})


def test_cli_help_and_invalid_command_behavior(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["not-a-command"])

    with pytest.raises(SystemExit):
        main(["--help"])

    result = main(["simulate", "--target", "8.8.8.8"])
    assert result == 2
    text = capsys.readouterr().err
    assert "target" in text.lower()


def test_public_target_rejected_in_live_mitigation(monkeypatch):
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    monkeypatch.setattr("ddos_detector.mitigation.os.name", "posix", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._interface_exists", lambda self, interface: interface == "lo", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.os.geteuid", lambda: 0, raising=False)
    result = manager.apply("8.8.8.8", "lo", "test")
    assert result["success"] is False
    assert result["error"] == "invalid_target"


def test_invalid_target_and_interface_rejected(monkeypatch):
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    monkeypatch.setattr("ddos_detector.mitigation.os.name", "posix", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._interface_exists", lambda self, interface: False, raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.os.geteuid", lambda: 0, raising=False)
    result = manager.apply("127.0.0.1", "missing0", "test")
    assert result["success"] is False
    assert result["error"] == "invalid_target"


def test_dry_run_and_disabled_do_not_call_subprocess(monkeypatch):
    manager = MitigationManager({"enabled": False, "dry_run": True, "mechanism": "nftables"})
    called = []

    def fake_run(*args, **kwargs):
        called.append(args[0])
        return None

    monkeypatch.setattr("ddos_detector.mitigation.subprocess.run", fake_run)
    assert manager.apply("127.0.0.1", "lo", "test")["success"] is False
    manager2 = MitigationManager({"enabled": True, "dry_run": True, "mechanism": "nftables"})
    assert manager2.apply("127.0.0.1", "lo", "test")["dry_run"] is True
    assert called == []


def test_live_linux_nftables_flow(monkeypatch):
    calls = []

    class Completed:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, shell=False, capture_output=False, text=None, check=False):
        calls.append(cmd)
        if cmd[:3] == ["nft", "-j", "list"]:
            payload = {"nftables": [{"chain": {"table": "ddos_detector", "name": "input", "rules": [{"handle": 14, "comment": "ddos_detector:live-1"}]}}]}
            return Completed(stdout=json.dumps(payload))
        return Completed()

    monkeypatch.setattr("ddos_detector.mitigation.os.name", "posix", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.os.geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._interface_exists", lambda self, interface: interface == "lo", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.subprocess.run", fake_run)

    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    result = manager.apply("127.0.0.1", "lo", "test")
    assert result["success"] is True
    assert manager.rules[0].status == "active"
    assert any(cmd[:4] == ["nft", "add", "table", "inet"] for cmd in calls)
    assert any(arg == '"ddos_detector:live-1"' for cmd in calls for arg in cmd)


def test_nft_rule_handles_parse_rule_objects_and_ignore_chain_handle(monkeypatch):
    class Completed:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    payload = {
        "nftables": [
            {"chain": {"family": "inet", "table": "ddos_detector", "name": "input", "handle": 1}},
            {"rule": {"family": "inet", "table": "ddos_detector", "chain": "input", "handle": 2, "comment": "ddos_detector:live-1"}},
            {"rule": {"family": "inet", "table": "ddos_detector", "chain": "input", "handle": 3, "comment": "ddos_detector:other"}},
        ]
    }

    def fake_run(cmd, shell=False, capture_output=False, text=None, check=False):
        return Completed(stdout=json.dumps(payload))

    monkeypatch.setattr("ddos_detector.mitigation.subprocess.run", fake_run)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")

    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    assert manager._nft_rule_handles("live-1") == ["2"]


def test_cleanup_all_discovers_application_rules_from_kernel_state(monkeypatch):
    calls = []

    class Completed:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    payload = {
        "nftables": [
            {"rule": {"table": "ddos_detector", "chain": "input", "handle": 2, "comment": "ddos_detector:live-1"}},
            {"rule": {"table": "ddos_detector", "chain": "input", "handle": 3, "comment": "ddos_detector:live-2"}},
            {"rule": {"table": "ddos_detector", "chain": "input", "handle": 4, "comment": "administrator-rule"}},
        ]
    }

    def fake_run(cmd, shell=False, capture_output=False, text=None, check=False):
        calls.append(cmd)
        if cmd[:3] == ["nft", "-j", "list"]:
            return Completed(stdout=json.dumps(payload))
        return Completed()

    monkeypatch.setattr("ddos_detector.mitigation.os.name", "posix", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.subprocess.run", fake_run)

    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    removed = manager.cleanup_all()
    assert removed == ["live-1", "live-2"]
    assert not manager.rules
    assert any(cmd[:6] == ["nft", "delete", "rule", "inet", "ddos_detector", "input"] for cmd in calls)
    assert any(cmd[6:] == ["handle", "2"] for cmd in calls if cmd[:6] == ["nft", "delete", "rule", "inet", "ddos_detector", "input"])
    assert any(cmd[6:] == ["handle", "3"] for cmd in calls if cmd[:6] == ["nft", "delete", "rule", "inet", "ddos_detector", "input"])
    assert not any(cmd[6:] == ["handle", "4"] for cmd in calls if cmd[:6] == ["nft", "delete", "rule", "inet", "ddos_detector", "input"])


def test_cleanup_removes_only_tracked_nftables_rule(monkeypatch):
    calls = []

    class Completed:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, shell=False, capture_output=False, text=None, check=False):
        calls.append(cmd)
        if cmd[:3] == ["nft", "-j", "list"]:
            payload = {"nftables": [{"chain": {"table": "ddos_detector", "name": "input", "rules": [{"handle": 12, "comment": "ddos_detector:live-1"}]}}]}
            return Completed(stdout=json.dumps(payload))
        return Completed()

    monkeypatch.setattr("ddos_detector.mitigation.os.name", "posix", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._interface_exists", lambda self, interface: interface == "lo", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.subprocess.run", fake_run)

    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    manager.rules.append(MitigationRule(rule_id="live-1", rule_type="nftables", target="127.0.0.1", interface="lo", reason="test", backend_id="12"))
    removed = manager.cleanup_all()
    assert removed == ["live-1"]
    assert not manager.rules
    assert any(cmd[:4] == ["nft", "delete", "rule", "inet"] for cmd in calls)
