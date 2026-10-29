"""Reproducible, bounded synthetic benchmark of the monitor processing loop.

This harness injects records into the real monitor loop without opening a
network capture socket. It measures Python-side processing, not Scapy or NIC
capture capacity.
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import sys
import threading
import time
from collections import deque
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from io import StringIO
from types import SimpleNamespace

if not sys.platform.startswith("linux"):
    raise SystemExit("Synthetic monitor benchmark currently requires Linux/WSL2.")

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import ddos_detector.main as monitor
from ddos_detector.models import PacketRecord
from ddos_detector.scoring import score_and_classify as score_pipeline

NORMAL_SECONDS = 10.0
BURST_SECONDS = 2.0
RECOVERY_SECONDS = 10.0
NORMAL_RATE = 5
BURST_RATE = 50
QUEUE_LIMIT = 256


class SyntheticCapture:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._queue = deque()
        self._done = False
        self.observed = 0
        self.processed = 0
        self.dropped = 0
        self.anomaly_started_at: float | None = None
        self.anomaly_ended_at: float | None = None
        self._producer = threading.Thread(target=self._produce, daemon=True)

    def __enter__(self):
        self._producer.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._producer.join(timeout=2)
        return False

    def _produce(self) -> None:
        phases = (
            (NORMAL_SECONDS, NORMAL_RATE, False),
            (BURST_SECONDS, BURST_RATE, True),
            (RECOVERY_SECONDS, NORMAL_RATE, False),
        )
        try:
            for duration, rate, is_burst in phases:
                phase_start = time.monotonic()
                if is_burst:
                    self.anomaly_started_at = phase_start
                elif self.anomaly_started_at is not None and self.anomaly_ended_at is None:
                    self.anomaly_ended_at = phase_start
                interval = 1.0 / rate
                next_packet_at = phase_start
                index = 0
                while next_packet_at < phase_start + duration:
                    delay = next_packet_at - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                    packet = PacketRecord(
                        timestamp=time.monotonic(),
                        src_ip=(
                            f"10.254.0.{index % 20 + 1}"
                            if is_burst
                            else f"10.254.0.{index % 2 + 1}"
                        ),
                        dst_ip="10.254.0.100",
                        src_port=20000 + index % 30000,
                        dst_port=443,
                        protocol="TCP",
                        packet_size=60,
                        tcp_flags="S",
                    )
                    with self._condition:
                        self.observed += 1
                        if len(self._queue) >= QUEUE_LIMIT:
                            self._queue.popleft()
                            self.dropped += 1
                        self._queue.append((time.monotonic(), packet))
                        self._condition.notify()
                    index += 1
                    next_packet_at += interval
        finally:
            with self._condition:
                self._done = True
                self._condition.notify_all()

    def wait_for_packets(self, timeout: float | None = None) -> bool:
        with self._condition:
            self._condition.wait_for(
                lambda: bool(self._queue) or self._done,
                timeout=max(0.0, timeout) if timeout is not None else None,
            )
            if self._queue:
                return True
            if self._done:
                raise KeyboardInterrupt
            return False

    def read_timed_packets(self, count: int = 100):
        packets = []
        with self._condition:
            while self._queue and len(packets) < count:
                packets.append(self._queue.popleft())
        self.processed += len(packets)
        return packets


def _rss_kib() -> int:
    with open("/proc/self/status", encoding="ascii") as status_file:
        for line in status_file:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("Unable to read process RSS from /proc/self/status")


def main() -> int:
    capture = SyntheticCapture()
    scored_windows = []
    real_platform_system = monitor.platform.system
    real_isdir = monitor.os.path.isdir
    real_lock = monitor._monitor_instance_lock
    real_score = monitor.score_and_classify
    real_manager_factory = monitor.MitigationManager
    cleanup_times = []

    def record_score(*args, **kwargs):
        result = score_pipeline(*args, **kwargs)
        scored_windows.append((time.monotonic(), result[1]))
        return result

    def counted_manager_factory(config):
        manager = real_manager_factory(config)
        original_cleanup = manager.cleanup_expired

        def count_cleanup():
            cleanup_times.append(time.monotonic())
            return original_cleanup()

        manager.cleanup_expired = count_cleanup
        return manager

    monitor.platform.system = lambda: "Linux"
    monitor.os.path.isdir = lambda path: True
    monitor._monitor_instance_lock = lambda interface: nullcontext()
    monitor.score_and_classify = record_score
    monitor.MitigationManager = counted_manager_factory
    cfg = SimpleNamespace(
        capture={"bpf_filter": ""},
        interface="synthetic0",
        window_seconds=1,
        slide_seconds=1,
        baseline={"history_windows": 30, "minimum_samples": 3},
        detection={"minimum_indicators": 2, "minimum_consecutive_windows": 1, "recovery_windows": 2},
        scoring={
            "weights": {
                "syn_rate": 1.0,
                "packet_rate": 0.8,
                "distributed_source": 1.0,
                "connection_rate": 0.7,
                "dest_concentration": 0.5,
            },
            "thresholds": {"normal": 0.2, "suspicious": 0.6},
        },
        weights={},
        thresholds={},
        mitigation={"enabled": True, "dry_run": True},
        alerts={"enabled": False, "email": {"enabled": False}},
    )

    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    rss_start = _rss_kib()
    try:
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            status = monitor._run_monitor(
                SimpleNamespace(interface="synthetic0"),
                cfg,
                capture_factory=lambda *args: capture,
            )
    finally:
        monitor.platform.system = real_platform_system
        monitor.os.path.isdir = real_isdir
        monitor._monitor_instance_lock = real_lock
        monitor.score_and_classify = real_score
        monitor.MitigationManager = real_manager_factory
    wall_seconds = time.perf_counter() - wall_start
    cpu_seconds = time.process_time() - cpu_start
    recovery_events = [
        timestamp
        for timestamp, classification in scored_windows
        if classification == "NORMAL"
        and capture.anomaly_ended_at is not None
        and timestamp >= capture.anomaly_ended_at
    ]
    recovery_latency = None
    if len(recovery_events) >= 2 and capture.anomaly_ended_at is not None:
        recovery_latency = recovery_events[1] - capture.anomaly_ended_at
    high_risk_times = [
        timestamp
        for timestamp, classification in scored_windows
        if classification == "HIGH_RISK"
    ]
    detection_latency = None
    if high_risk_times and capture.anomaly_started_at is not None:
        detection_latency = high_risk_times[0] - capture.anomaly_started_at

    result = {
        "label": "synthetic-only; no sockets or network packets",
        "machine": platform.platform(),
        "python": sys.version.split()[0],
        "os": platform.system(),
        "configuration": {
            "window_seconds": 1,
            "slide_seconds": 1,
            "baseline_minimum_samples": 3,
            "normal_rate_packets_per_second": NORMAL_RATE,
            "burst_rate_packets_per_second": BURST_RATE,
            "normal_seconds_before_and_after_burst": NORMAL_SECONDS,
            "burst_seconds": BURST_SECONDS,
            "capture_queue_limit": QUEUE_LIMIT,
        },
        "monitor_status": status,
        "wall_seconds": round(wall_seconds, 3),
        "process_cpu_seconds": round(cpu_seconds, 3),
        "process_cpu_percent_of_one_core": round(100 * cpu_seconds / wall_seconds, 2),
        "rss_start_kib": rss_start,
        "rss_end_kib": _rss_kib(),
        "packets_observed": capture.observed,
        "packets_processed": capture.processed,
        "capture_queue_drops": capture.dropped,
        "scored_windows": len(scored_windows),
        "scored_classifications": [classification for _, classification in scored_windows],
        "cleanup_calls_total": len(cleanup_times),
        "scheduled_cleanup_calls_per_minute": round(
            max(0, len(cleanup_times) - 2) * 60 / wall_seconds, 2
        ),
        "detection_latency_seconds": (
            round(detection_latency, 3) if detection_latency is not None else None
        ),
        "recovery_latency_seconds": (
            round(recovery_latency, 3) if recovery_latency is not None else None
        ),
        "cleanup_measurement_note": (
            "scheduled rate excludes one startup and one shutdown cleanup; "
            "dry-run manager made no firewall changes"
        ),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == 0 else status


if __name__ == "__main__":
    raise SystemExit(main())
