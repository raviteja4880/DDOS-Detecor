"""Synthetic-only integration coverage for the connected detector pipeline."""

import pathlib
import sys

import pytest
import requests

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.aggregator import SlidingWindowAggregator, compute_window_metrics
from ddos_detector.alerts import (
    ALERT_LAST_SENT,
    INCIDENT_STATE,
    maybe_emit_alert,
    mark_normal_window,
)
from ddos_detector.baseline import BaselineEngine
from ddos_detector.detector import analyze_window
from ddos_detector.feature_extractor import extract_features
from ddos_detector.models import PacketRecord
from ddos_detector.packet_parser import parse_packet
from ddos_detector.scoring import score_and_classify


@pytest.fixture(autouse=True)
def clear_incident_state():
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    yield
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()


def _records(
    *,
    count: int,
    protocol: str,
    sources: int,
    flags: str | None = None,
    packet_size: int = 100,
) -> list[PacketRecord]:
    return [
        PacketRecord(
            timestamp=index / 10,
            src_ip=f"10.20.0.{index % sources + 1}",
            dst_ip="10.20.1.10",
            src_port=20000 + index % 40000,
            dst_port=443 if protocol == "TCP" else 53,
            protocol=protocol,
            packet_size=packet_size,
            tcp_flags=flags,
        )
        for index in range(count)
    ]


def _aggregate(records: list[PacketRecord]):
    features = [extract_features(record) for record in records]
    return compute_window_metrics(features, window_seconds=5)


def _score(metric, baseline):
    detection = analyze_window(metric, baseline)
    score, classification = score_and_classify(
        detection.indicators,
        weights={
            "syn_rate": 1.0,
            "packet_rate": 0.8,
            "distributed_source": 1.0,
            "connection_rate": 0.7,
            "dest_concentration": 0.5,
        },
        thresholds={"normal": 0.2, "suspicious": 0.6},
    )
    return detection, score, classification


def _alert(classification, score, reasons, clock):
    return maybe_emit_alert(
        classification,
        score,
        reasons,
        current_metrics={"packets_per_sec": 60},
        baseline={"packets_per_sec": 4},
        alert_cfg={
            "email": {
                "enabled": True,
                "provider": "brevo",
                "api_key": "test-key-not-a-real-credential",
                "from": "detector@example.invalid",
                "to": "recipient@example.invalid",
            }
        },
        context={
            "interface": "synthetic0",
            "target_ips": ["10.20.1.10"],
            "source_ips": ["10.20.0.1"],
        },
        clock=lambda: clock,
    )


def test_synthetic_connected_pipeline_bootstrap_detection_alert_recovery(monkeypatch):
    """Run synthetic records through extraction, aggregation, detection and alerting."""
    sends = []
    responses = [requests.Timeout("synthetic delivery failure")]

    def fake_post(url, **kwargs):
        sends.append((url, kwargs))
        if responses:
            raise responses.pop(0)

        class Accepted:
            status_code = 201

        return Accepted()

    monkeypatch.setattr(requests, "post", fake_post)
    normal_records = _records(count=20, protocol="UDP", sources=2)
    normal_metric = _aggregate(normal_records)
    baseline = BaselineEngine(history_windows=20, minimum_samples=3)

    assert not baseline.observe_bootstrap(normal_metric)
    assert not baseline.observe_bootstrap(normal_metric)
    assert baseline.observe_bootstrap(normal_metric)
    assert baseline.is_ready()
    normal_detection, _, normal_classification = _score(normal_metric, baseline)
    assert normal_classification == "NORMAL"

    # Empty and low-volume traffic should remain observable and not become an
    # attack label solely due to a low-volume ratio against the baseline.
    empty_metric = compute_window_metrics([], window_seconds=5)
    assert _score(empty_metric, baseline)[2] == "NORMAL"
    low_volume = _aggregate(_records(count=1, protocol="UDP", sources=1))
    assert _score(low_volume, baseline)[2] == "NORMAL"

    single_source = _aggregate(
        _records(count=300, protocol="UDP", sources=1, packet_size=300)
    )
    _, _, single_classification = _score(single_source, baseline)
    assert single_classification == "SUSPICIOUS"

    multi_source_syn = _aggregate(
        _records(count=300, protocol="TCP", sources=30, flags="S", packet_size=60)
    )
    detection, score, classification = _score(multi_source_syn, baseline)
    assert classification == "HIGH_RISK"
    assert "SYN-rate anomaly" in detection.triggered_indicators
    assert "distributed-source anomaly" in detection.triggered_indicators

    first_alert = _alert(classification, score, detection.triggered_indicators, 100.0)
    assert first_alert is not None
    # Delivery failed, so repeating the same active incident retries rather
    # than consuming a success-shaped cooldown.
    assert _alert(classification, score, detection.triggered_indicators, 101.0) is not None
    assert len(sends) == 2
    assert len(ALERT_LAST_SENT) == 1

    for _ in range(100):
        _alert(classification, score, detection.triggered_indicators, 102.0)
    assert len(sends) == 2

    # A UDP-heavy distributed burst is an independent synthetic detection case.
    udp_burst = _aggregate(
        _records(count=300, protocol="UDP", sources=30, packet_size=500)
    )
    udp_detection, _, udp_classification = _score(udp_burst, baseline)
    assert udp_classification in {"SUSPICIOUS", "HIGH_RISK"}
    assert udp_detection.triggered_indicators

    mark_normal_window("synthetic0", required_windows=2)
    assert INCIDENT_STATE
    mark_normal_window("synthetic0", required_windows=2)
    assert not INCIDENT_STATE
    _alert(classification, score, detection.triggered_indicators, 103.0)
    assert len(sends) == 3

    assert normal_detection.classification == "NORMAL"


def test_synthetic_burst_crossing_sliding_boundaries_reaches_aggregation():
    windows = SlidingWindowAggregator(window_seconds=4, slide_seconds=2, started_at=0.0)
    first = extract_features(
        PacketRecord(3.9, "10.20.0.1", "10.20.1.10", protocol="TCP", packet_size=60, tcp_flags="S")
    )
    second = extract_features(
        PacketRecord(4.1, "10.20.0.2", "10.20.1.10", protocol="TCP", packet_size=60, tcp_flags="S")
    )
    windows.add_packet(first, received_at=3.9)
    windows.add_packet(second, received_at=4.1)

    emitted = windows.pop_ready(10.0)
    assert [metric.packets for metric in emitted] == [1, 2, 1, 0]
    assert [metric.syn_packets for metric in emitted] == [1, 2, 1, 0]


def test_synthetic_malformed_or_unsupported_packets_are_rejected():
    with pytest.raises(ValueError, match="missing source IP"):
        parse_packet({"dst": "10.20.1.10", "protocol": "UDP"})
    with pytest.raises(ValueError, match="Unsupported packet type"):
        extract_features(object())


def test_warmup_and_empty_windows_do_not_claim_normal_before_ready():
    baseline = BaselineEngine(history_windows=10, minimum_samples=3)
    empty_metric = compute_window_metrics([], window_seconds=5)
    for _ in range(2):
        assert analyze_window(empty_metric, baseline).classification == "BASELINE_WARMUP"
        assert not baseline.observe_bootstrap(empty_metric)
    assert analyze_window(empty_metric, baseline).classification == "BASELINE_WARMUP"
    assert baseline.observe_bootstrap(empty_metric)
    assert analyze_window(empty_metric, baseline).classification == "NORMAL"
