import sys
import os
import types
import time

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
