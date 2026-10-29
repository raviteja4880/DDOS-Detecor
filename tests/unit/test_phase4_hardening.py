import io
import json
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import pytest

from ddos_detector.config import Config, validate_config
from ddos_detector.main import _run_monitor, build_parser, main
from ddos_detector.mitigation import MitigationManager, MitigationRule
from ddos_detector.models import PacketRecord, WindowMetric


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
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._is_linux", lambda self: True)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._interface_exists", lambda self, interface: interface == "lo", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.os.geteuid", lambda: 0, raising=False)
    result = manager.apply("8.8.8.8", "lo", "test")
    assert result["success"] is False
    assert result["error"] == "invalid_target"


def test_invalid_target_and_interface_rejected(monkeypatch):
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._is_linux", lambda self: True)
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
            add_calls = [call for call in calls if call[1:3] == ["add", "rule"]]
            if not add_calls:
                return Completed(stdout=json.dumps({"nftables": []}))
            add_rule = add_calls[-1]
            payload = {"nftables": [{"chain": {"table": "ddos_detector", "name": "input", "rules": [{"handle": 14, "comment": add_rule[-1].strip('"')}]}}]}
            return Completed(stdout=json.dumps(payload))
        return Completed()

    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._is_linux", lambda self: True)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.os.geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._has_root_privileges", lambda self: True)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._interface_exists", lambda self, interface: interface == "lo", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.subprocess.run", fake_run)

    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    result = manager.apply("127.0.0.1", "lo", "test")
    assert result["success"] is True
    assert manager.rules[0].status == "active"
    assert any(cmd[:4] == ["nft", "add", "table", "inet"] for cmd in calls)
    assert any(arg.startswith('"ddos_detector:live-') for cmd in calls for arg in cmd)


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

    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._is_linux", lambda self: True)
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

    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._is_linux", lambda self: True)
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


def test_cleanup_expired_recovers_expired_rule_after_restart(monkeypatch):
    calls = []
    expires = int(__import__("time").time()) - 10

    class Completed:
        returncode = 0
        stderr = ""
        stdout = json.dumps({
            "nftables": [{
                "rule": {
                    "table": "ddos_detector",
                    "chain": "input",
                    "handle": 20,
                    "comment": f"ddos_detector:source-live-{expires}-abcdef123456",
                }
            }]
        })

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return Completed()

    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._is_linux", lambda self: True)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.subprocess.run", fake_run)
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    assert manager.cleanup_expired()
    assert any(cmd[1:3] == ["delete", "rule"] for cmd in calls)


def test_cleanup_already_deleted_rule_is_idempotent(monkeypatch):
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "No such file or directory"

    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._is_linux", lambda self: True)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: True)
    monkeypatch.setattr("ddos_detector.mitigation.subprocess.run", lambda *args, **kwargs: Completed())
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    assert manager.cleanup_all() == []
    assert manager.last_cleanup_error is None


def test_monitor_rejects_windows_live_capture(monkeypatch, capsys):
    monkeypatch.setattr("ddos_detector.main.platform.system", lambda: "Windows", raising=False)
    result = main(["monitor", "--interface", "eth0"])
    captured = capsys.readouterr()
    assert result == 2
    assert "Linux/WSL2" in captured.err


def test_monitor_rejects_missing_interface(monkeypatch, capsys):
    monkeypatch.setattr("ddos_detector.main.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.main.os.path.isdir", lambda path: False)
    result = main(["monitor", "--interface", "missing0"])
    captured = capsys.readouterr()
    assert result == 2
    assert "does not exist" in captured.err


def test_packet_capture_reads_queued_packets():
    from ddos_detector.packet_capture import LinuxPacketCapture

    capture = LinuxPacketCapture("lo")
    capture._on_packet("packet-1")
    capture._on_packet("packet-2")
    assert capture.read_packets(10) == ["packet-1", "packet-2"]
    assert capture.read_packets(10) == []


def test_monitor_uses_detected_normal_window(monkeypatch, tmp_path):
    monkeypatch.setenv("DDOS_DETECTOR_LOCK_DIR", str(tmp_path))
    clock = [0.0]
    monkeypatch.setattr("ddos_detector.main.time.monotonic", lambda: clock[0])

    class FakeCapture:
        def __init__(self):
            self.calls = 0
            self.waits = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def wait_for_packets(self, timeout):
            self.waits += 1
            clock[0] += 4.9 if self.waits == 1 else timeout

        def read_packets(self, count=100):
            self.calls += 1
            if self.calls == 1:
                return [PacketRecord(timestamp=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=80, protocol="TCP", packet_size=128, tcp_flags="S")]
            if self.calls == 2:
                return []
            raise KeyboardInterrupt()

    monkeypatch.setattr("ddos_detector.main.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.main.os.path.isdir", lambda path: True)
    monkeypatch.setattr("ddos_detector.main.open_capture", lambda interface, bpf_filter="": FakeCapture())
    monkeypatch.setattr("ddos_detector.main.BaselineEngine.is_ready", lambda self: True)
    monkeypatch.setattr("ddos_detector.main.analyze_window", lambda current, baseline, minimum_indicators=2, allow_provisional=False: type("D", (), {"indicators": [], "triggered_indicators": [], "reason": "No anomaly detected", "score": 0.0, "classification": "NORMAL"})())
    monkeypatch.setattr("ddos_detector.main.score_and_classify", lambda indicators, weights=None, thresholds=None: (0.05, "NORMAL"))
    monkeypatch.setattr("ddos_detector.main.maybe_emit_alert", lambda *args, **kwargs: None)
    cfg = Config(interface="lo")
    result = _run_monitor(type("Args", (), {"interface": "lo"})(), cfg)
    assert result == 0
