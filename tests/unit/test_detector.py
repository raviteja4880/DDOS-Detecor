import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.baseline import BaselineEngine
from ddos_detector.detector import analyze_window
from ddos_detector.models import WindowMetric


def make_metric(packets_per_sec, bytes_per_sec, syn_packets, connection_attempts, unique_src_ips, unique_dst_ips, dest_concentration=0.2, packets=100):
    return WindowMetric(
        window_seconds=5,
        packets=packets,
        bytes=int(bytes_per_sec * 5),
        packets_per_sec=packets_per_sec,
        bytes_per_sec=bytes_per_sec,
        tcp_packets=packets,
        udp_packets=0,
        icmp_packets=0,
        syn_packets=syn_packets,
        connection_attempts=connection_attempts,
        unique_src_ips=unique_src_ips,
        unique_dst_ips=unique_dst_ips,
        dst_port_distribution={80: 10},
        avg_packet_size=200,
        burst_intensity=1.0,
        dest_concentration=dest_concentration,
        raw=None,
    )


def test_detector_normal_traffic():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    engine.update(make_metric(150, 90000, 10, 12, 8, 3), is_anomalous=False)
    engine.update(make_metric(160, 92000, 11, 13, 9, 4), is_anomalous=False)
    current = make_metric(170, 94000, 12, 15, 9, 4)
    result = analyze_window(current, engine, minimum_indicators=2)
    assert result.classification in {"NORMAL", "SUSPICIOUS"}


def test_detector_detects_high_packet_rate_and_source_distribution():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    engine.update(make_metric(150, 90000, 10, 12, 8, 3), is_anomalous=False)
    engine.update(make_metric(170, 93000, 11, 13, 9, 4), is_anomalous=False)
    current = make_metric(4800, 1200000, 2100, 1800, 137, 10, dest_concentration=0.62)
    result = analyze_window(current, engine, minimum_indicators=2)
    assert any(item.triggered for item in result.indicators)
    assert result.classification in {"SUSPICIOUS", "HIGH_RISK"}


def test_detector_requires_multiple_indicators_for_high_risk():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    engine.update(make_metric(150, 90000, 10, 12, 8, 3), is_anomalous=False)
    engine.update(make_metric(170, 93000, 11, 13, 9, 4), is_anomalous=False)
    current = make_metric(300, 100000, 12, 12, 10, 4, dest_concentration=0.14)
    result = analyze_window(current, engine, minimum_indicators=2)
    assert result.classification == "NORMAL"


def test_distributed_source_requires_at_least_two_sources():
    engine = BaselineEngine(history_windows=10, minimum_samples=1)
    engine.update(make_metric(100, 20000, 5, 5, 0, 1), is_anomalous=False)

    result = analyze_window(
        make_metric(100, 20000, 5, 5, 1, 1),
        engine,
        minimum_indicators=1,
    )

    distributed = next(item for item in result.indicators if item.name == "distributed-source anomaly")
    assert distributed.triggered is False


def test_distributed_source_triggers_for_significant_multi_source_increase():
    engine = BaselineEngine(history_windows=10, minimum_samples=1)
    engine.update(make_metric(100, 20000, 5, 5, 1, 1), is_anomalous=False)

    result = analyze_window(
        make_metric(100, 20000, 5, 5, 3, 1),
        engine,
        minimum_indicators=1,
    )

    distributed = next(item for item in result.indicators if item.name == "distributed-source anomaly")
    assert distributed.triggered is True


def test_other_indicators_are_unchanged_for_single_source():
    engine = BaselineEngine(history_windows=10, minimum_samples=1)
    engine.update(make_metric(100, 20000, 5, 5, 1, 1), is_anomalous=False)

    result = analyze_window(
        make_metric(1000, 200000, 5, 5, 1, 1),
        engine,
        minimum_indicators=1,
    )

    packet_rate = next(item for item in result.indicators if item.name == "packet-rate anomaly")
    distributed = next(item for item in result.indicators if item.name == "distributed-source anomaly")
    assert packet_rate.triggered is True
    assert distributed.triggered is False


def test_empty_baseline_stays_in_warmup():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    result = analyze_window(make_metric(1000, 200000, 50, 50, 10, 1), engine)
    assert result.classification == "NORMAL"
    assert result.triggered_indicators == []
    assert "warm-up" in result.reason


def test_packet_and_byte_burst_without_strong_signal_is_not_high_risk():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    engine.update(make_metric(100, 20000, 5, 5, 1, 1), is_anomalous=False)
    engine.update(make_metric(100, 20000, 5, 5, 1, 1), is_anomalous=False)
    result = analyze_window(make_metric(1000, 200000, 5, 5, 1, 1), engine)
    assert result.classification == "SUSPICIOUS"


def test_multi_source_flood_with_protocol_signals_is_high_risk():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    engine.update(make_metric(100, 20000, 5, 5, 1, 1), is_anomalous=False)
    engine.update(make_metric(100, 20000, 5, 5, 1, 1), is_anomalous=False)
    result = analyze_window(make_metric(1200, 240000, 80, 80, 10, 1, dest_concentration=1.0), engine)
    assert result.classification == "HIGH_RISK"
    assert len(result.triggered_indicators) >= 3
    assert all(item.explanation and item.threshold > 0 for item in result.indicators)


def test_high_risk_recovers_to_normal_after_spike():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    normal = make_metric(100, 20000, 5, 5, 1, 1)
    engine.update(normal, is_anomalous=False)
    engine.update(normal, is_anomalous=False)
    spike = analyze_window(make_metric(1200, 240000, 80, 80, 10, 1, dest_concentration=1.0), engine)
    assert spike.classification == "HIGH_RISK"
    recovery = analyze_window(normal, engine)
    assert recovery.classification == "NORMAL"
