import sys
import os
import types
import time
import tempfile
import subprocess
import select
import pytest

from contextlib import nullcontext
from types import SimpleNamespace

# Ensure package import finds the local 'src' folder when pytest runs this file directly
SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def test_monitor_uses_injected_capture(monkeypatch):
    # Ensure platform checks pass
    monkeypatch.setattr("os.path.isdir", lambda path: True)
    monkeypatch.setattr("platform.system", lambda: "Linux")

    # Minimal config object expected by _run_monitor
    cfg = SimpleNamespace(
        capture={"bpf_filter": ""},
        interface="eth0",
        window_seconds=0.01,
        baseline={"history_windows": 1, "minimum_samples": 0},
        detection={"minimum_indicators": 2},
        scoring={"weights": {}, "thresholds": {}},
        weights={},
        thresholds={},
        logging={"level": "INFO", "json": False},
    )

    args = SimpleNamespace(interface="eth0", config="config/config.yaml")

    created = {}

    class FakeCapture:
        def __init__(self, interface, bpf_filter=""):
            created['interface'] = interface
            created['bpf_filter'] = bpf_filter
            self.calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read_packets(self, count=100):
            # first call: return empty list, second call: raise KeyboardInterrupt to stop
            self.calls += 1
            if self.calls == 1:
                return []
            raise KeyboardInterrupt()

    def fake_factory(interface, bpf_filter=""):
        return FakeCapture(interface, bpf_filter)

    # Run monitor; should use fake_factory and exit via KeyboardInterrupt during the test
    from ddos_detector.main import _run_monitor

    result = _run_monitor(args, cfg, capture_factory=fake_factory)

    # run should return 0 on graceful KeyboardInterrupt
    assert result == 0
    assert created.get('interface') == 'eth0'
    assert created.get('bpf_filter') == ''


def test_idle_monitor_waits_and_schedules_expiration_cleanup(monkeypatch, capsys):
    monkeypatch.setattr("os.path.isdir", lambda path: True)
    monkeypatch.setattr("platform.system", lambda: "Linux")
    clock = [0.0]
    monkeypatch.setattr("ddos_detector.main.time.monotonic", lambda: clock[0])

    class FakeManager:
        cleanup_calls = []

        def __init__(self, config):
            pass

        def cleanup_expired(self):
            self.cleanup_calls.append(None)
            return []

    monkeypatch.setattr("ddos_detector.main.MitigationManager", FakeManager)

    class FakeCapture:
        def __init__(self, interface, bpf_filter=""):
            self.wait_calls = 0
            self.read_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def wait_for_packets(self, timeout):
            assert timeout > 0
            self.wait_calls += 1
            clock[0] += timeout
            return False

        def read_packets(self, count=100):
            self.read_calls += 1
            if self.read_calls == 7:
                raise KeyboardInterrupt()
            return []

    capture = FakeCapture("eth0")
    cfg = SimpleNamespace(
        capture={"bpf_filter": ""},
        interface="eth0",
        window_seconds=1,
        slide_seconds=1,
        baseline={"history_windows": 10, "minimum_samples": 1},
        detection={"minimum_indicators": 2},
        scoring={"weights": {}, "thresholds": {}},
        weights={},
        thresholds={},
        mitigation={"enabled": True, "dry_run": True},
        alerts={"enabled": False, "email": {"enabled": False}},
    )
    args = SimpleNamespace(interface="eth0")

    from ddos_detector.main import _run_monitor

    monkeypatch.setattr("ddos_detector.main._monitor_instance_lock", lambda interface: nullcontext())
    result = _run_monitor(args, cfg, capture_factory=lambda *args: capture)

    assert result == 0
    assert capture.wait_calls == capture.read_calls == 7
    assert len(FakeManager.cleanup_calls) == 3  # startup, scheduled, and shutdown
    assert len(FakeManager.cleanup_calls) < capture.read_calls
    assert "Stopping live monitor." in capsys.readouterr().out


def test_monitor_extracts_packets_before_aggregation(monkeypatch, capsys):
    monkeypatch.setattr("os.path.isdir", lambda path: True)
    monkeypatch.setattr("platform.system", lambda: "Linux")
    clock = [0.0]
    monkeypatch.setattr("ddos_detector.main.time.monotonic", lambda: clock[0])

    class FakeCapture:
        def __init__(self, interface, bpf_filter=""):
            self.read_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def wait_for_packets(self, timeout):
            clock[0] += min(timeout, 0.5)
            return False

        def read_packets(self, count=100):
            self.read_calls += 1
            if self.read_calls == 1:
                return [{"timestamp": 1.0, "src": "10.0.0.1", "dst": "10.0.0.2",
                         "protocol": 6, "len": 60, "flags": "SA"}]
            if self.read_calls == 2:
                return []
            raise KeyboardInterrupt()

    cfg = SimpleNamespace(
        capture={"bpf_filter": ""},
        interface="eth0",
        window_seconds=1,
        slide_seconds=1,
        baseline={"history_windows": 10, "minimum_samples": 1},
        detection={"minimum_indicators": 2},
        scoring={"weights": {}, "thresholds": {}},
        weights={},
        thresholds={},
        mitigation={"enabled": False, "dry_run": True},
        alerts={"enabled": False, "email": {"enabled": False}},
    )
    from ddos_detector.main import _run_monitor

    monkeypatch.setattr("ddos_detector.main._monitor_instance_lock", lambda interface: nullcontext())
    result = _run_monitor(
        SimpleNamespace(interface="eth0"),
        cfg,
        capture_factory=lambda *args: FakeCapture(*args),
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "packet-rate: 1.0 pps" in output
    assert "SYN-rate: 0.0/s" in output
    assert "classification: BASELINE_WARMUP" in output


def test_monitor_keeps_empty_windows_in_warmup_until_baseline_is_ready(monkeypatch, capsys):
    monkeypatch.setattr("ddos_detector.main.os.path.isdir", lambda path: True)
    monkeypatch.setattr("ddos_detector.main.platform.system", lambda: "Linux")
    monkeypatch.setattr("ddos_detector.main._monitor_instance_lock", lambda interface: nullcontext())
    clock = [0.0]
    monkeypatch.setattr("ddos_detector.main.time.monotonic", lambda: clock[0])

    class FakeCapture:
        def __init__(self, *args):
            self.read_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def wait_for_packets(self, timeout):
            clock[0] += timeout
            return False

        def read_timed_packets(self, count=100):
            self.read_calls += 1
            if self.read_calls == 5:
                raise KeyboardInterrupt()
            return []

    import ddos_detector.main as monitor_module

    calls = []
    real_analyze_window = monitor_module.analyze_window

    def observe_analyze(current, baseline, minimum_indicators=2):
        calls.append(baseline.is_ready())
        return real_analyze_window(current, baseline, minimum_indicators)

    monkeypatch.setattr("ddos_detector.main.analyze_window", observe_analyze)
    monkeypatch.setattr("ddos_detector.main.score_and_classify", lambda *args, **kwargs: (0.0, "NORMAL"))
    monkeypatch.setattr("ddos_detector.main.mark_normal_window", lambda *args, **kwargs: None)
    cfg = SimpleNamespace(
        capture={"bpf_filter": ""},
        interface="eth0",
        window_seconds=1,
        slide_seconds=1,
        baseline={"history_windows": 10, "minimum_samples": 3},
        detection={"minimum_indicators": 2, "minimum_consecutive_windows": 1},
        scoring={"weights": {}, "thresholds": {}},
        weights={},
        thresholds={},
        mitigation={"enabled": False, "dry_run": True},
        alerts={"enabled": False, "email": {"enabled": False}},
    )

    from ddos_detector.main import _run_monitor

    result = _run_monitor(
        SimpleNamespace(interface="eth0"),
        cfg,
        capture_factory=lambda *args: FakeCapture(*args),
    )

    assert result == 0
    assert calls == [True]
    output = capsys.readouterr().out
    assert output.count("classification: BASELINE_WARMUP") == 3
    assert "classification: NORMAL" in output


def test_monitor_instance_lock_rejects_duplicate_and_releases(monkeypatch):
    if not sys.platform.startswith("linux"):
        pytest.skip("fcntl singleton locking is Linux-specific")
    from ddos_detector.main import _monitor_instance_lock

    with tempfile.TemporaryDirectory() as lock_dir:
        monkeypatch.setenv("DDOS_DETECTOR_LOCK_DIR", lock_dir)
        with _monitor_instance_lock("eth0"):
            try:
                with _monitor_instance_lock("eth0"):
                    assert False, "duplicate monitor lock unexpectedly acquired"
            except RuntimeError as exc:
                assert "already monitoring interface 'eth0'" in str(exc)

        with _monitor_instance_lock("eth0"):
            pass


def test_monitor_instance_lock_excludes_another_process_and_reuses_stale_lock_file(
    monkeypatch, tmp_path
):
    if not sys.platform.startswith("linux"):
        pytest.skip("fcntl process locking is Linux-specific")

    from ddos_detector.main import _monitor_instance_lock

    monkeypatch.setenv("DDOS_DETECTOR_LOCK_DIR", str(tmp_path))
    child_code = (
        "import time; "
        "from ddos_detector.main import _monitor_instance_lock; "
        "lock = _monitor_instance_lock('synthetic0'); "
        "lock.__enter__(); "
        "print('LOCK_HELD', flush=True); "
        "time.sleep(30)"
    )
    child_env = os.environ.copy()
    child_env["PYTHONPATH"] = os.pathsep.join(
        [SRC_ROOT, child_env.get("PYTHONPATH", "")]
    )
    process = subprocess.Popen(
        [sys.executable, "-c", child_code],
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        ready, _, _ = select.select([process.stdout], [], [], 10)
        assert ready, "child process did not acquire the monitor lock"
        assert process.stdout.readline().strip() == "LOCK_HELD"
        with pytest.raises(RuntimeError, match="already monitoring interface 'synthetic0'"):
            with _monitor_instance_lock("synthetic0"):
                pytest.fail("second process acquired the active interface lock")
    finally:
        process.terminate()
        process.wait(timeout=10)

    lock_files = list(tmp_path.glob("ddos_detector_*.lock"))
    assert len(lock_files) == 1
    with _monitor_instance_lock("synthetic0"):
        pass
