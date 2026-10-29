import sys
import pathlib
from dataclasses import replace

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.aggregator import compute_window_metrics
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
    assert result.classification == "BASELINE_WARMUP"
    assert result.triggered_indicators == []
    assert "warm-up" in result.reason


def make_bootstrap_metric(packets=50, packet_size=100, syn_packets=5, sources=2):
    duration = 5
    total_bytes = packets * packet_size
    return WindowMetric(
        window_seconds=duration,
        packets=packets,
        bytes=total_bytes,
        packets_per_sec=packets / duration,
        bytes_per_sec=total_bytes / duration,
        tcp_packets=packets,
        udp_packets=0,
        icmp_packets=0,
        syn_packets=syn_packets,
        connection_attempts=syn_packets,
        unique_src_ips=min(sources, packets),
        unique_dst_ips=1 if packets else 0,
        dst_port_distribution={80: packets} if packets else {},
        avg_packet_size=float(packet_size),
        burst_intensity=1.0 if packets else 0.0,
        dest_concentration=1.0 if packets else 0.0,
        raw=None,
    )


def test_bootstrap_rejects_an_extreme_first_observation():
    engine = BaselineEngine(history_windows=10, minimum_samples=3)
    extreme_first = make_bootstrap_metric(packets=5000, packet_size=1500, syn_packets=2500, sources=100)
    normal = make_bootstrap_metric()

    assert not engine.observe_bootstrap(extreme_first)
    assert not engine.observe_bootstrap(normal)
    assert not engine.observe_bootstrap(normal)
    assert engine.observe_bootstrap(normal)
    assert engine.is_ready()
    assert [sample.packets_per_sec for sample in engine.history] == [10.0, 10.0, 10.0]
    assert all(sample is not extreme_first for sample in engine.history)


def test_bootstrap_rejects_extreme_burst_during_warmup():
    engine = BaselineEngine(history_windows=10, minimum_samples=4)
    normal = make_bootstrap_metric()
    for _ in range(3):
        engine.observe_bootstrap(normal)
    assert len(engine.history) == 3

    before = engine.snapshot().mean.copy()
    burst = make_bootstrap_metric(packets=5000, packet_size=1500, syn_packets=2500, sources=100)
    assert not engine.observe_bootstrap(burst)
    assert engine.snapshot().mean == before
    assert engine.observe_bootstrap(normal)
    assert engine.is_ready()
    assert engine.snapshot().mean["packets_per_sec"] == 10.0


def test_all_zero_and_empty_observations_can_bootstrap():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    empty = compute_window_metrics([], window_seconds=5)

    assert not engine.observe_bootstrap(empty)
    assert not engine.observe_bootstrap(empty)
    assert engine.observe_bootstrap(empty)
    assert engine.is_ready()
    assert len(engine.history) == 3
    assert engine.snapshot().mean["packets_per_sec"] == 0.0


def test_bootstrap_rejects_invalid_and_non_finite_metrics():
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    valid = make_bootstrap_metric()
    invalid_metrics = (
        replace(valid, packets_per_sec=float("nan")),
        replace(valid, bytes_per_sec=float("inf")),
        replace(valid, packets=-1),
        replace(valid, packets_per_sec=999.0),
        replace(valid, syn_packets=valid.tcp_packets + 1),
    )

    for metric in invalid_metrics:
        assert not engine.observe_bootstrap(metric)
        assert engine.history == []

    for _ in range(3):
        engine.observe_bootstrap(valid)
    assert engine.is_ready()
    assert len(engine.history) == 3


def test_normal_bootstrap_transitions_from_warmup_to_normal():
    engine = BaselineEngine(history_windows=10, minimum_samples=3)
    normal = make_bootstrap_metric()

    assert analyze_window(normal, engine).classification == "BASELINE_WARMUP"
    for _ in range(2):
        assert not engine.observe_bootstrap(normal)
        assert analyze_window(normal, engine).classification == "BASELINE_WARMUP"
    assert engine.observe_bootstrap(normal)
    assert analyze_window(normal, engine).classification == "NORMAL"


def test_high_risk_is_detected_on_the_first_window_after_bootstrap():
    engine = BaselineEngine(history_windows=10, minimum_samples=3)
    normal = make_bootstrap_metric()
    for _ in range(3):
        engine.observe_bootstrap(normal)
    assert engine.is_ready()

    burst = make_bootstrap_metric(
        packets=6000,
        packet_size=1000,
        syn_packets=3000,
        sources=100,
    )
    burst = replace(burst, dest_concentration=1.0)
    result = analyze_window(burst, engine)
    assert result.classification == "HIGH_RISK"


def test_detected_anomaly_does_not_contaminate_bootstrap_baseline():
    engine = BaselineEngine(history_windows=10, minimum_samples=3)
    normal = make_bootstrap_metric()
    for _ in range(3):
        engine.observe_bootstrap(normal)
    before = engine.snapshot().mean.copy()

    burst = make_bootstrap_metric(
        packets=6000,
        packet_size=1000,
        syn_packets=3000,
        sources=100,
    )
    result = analyze_window(burst, engine)
    assert result.classification == "HIGH_RISK"
    assert not engine.update(burst, is_anomalous=True)
    assert engine.snapshot().mean == before
    assert engine.update(normal, is_anomalous=False)


def test_bootstrap_results_are_deterministic_for_same_sequence():
    sequence = [
        make_bootstrap_metric(packets=5000, packet_size=1500, syn_packets=2500, sources=100),
        make_bootstrap_metric(),
        make_bootstrap_metric(),
        make_bootstrap_metric(),
    ]

    def run_sequence():
        engine = BaselineEngine(history_windows=10, minimum_samples=3)
        accepted = [engine.observe_bootstrap(metric) for metric in sequence]
        return accepted, engine.snapshot().mean, engine.snapshot().sample_count

    assert run_sequence() == run_sequence()


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


def test_low_volume_zero_baseline_is_not_permanently_suspicious():
    engine = BaselineEngine(history_windows=60, minimum_samples=2)
    idle = make_metric(0, 0, 0, 0, 0, 0, dest_concentration=0.0, packets=0)
    engine.update(idle, is_anomalous=False)
    engine.update(idle, is_anomalous=False)

    result = analyze_window(
        make_metric(1.6, 320, 0, 0, 1, 1, dest_concentration=1.0, packets=8),
        engine,
    )

    assert result.classification == "NORMAL"
    assert result.triggered_indicators == []
    assert all(indicator.deviation == 0.0 for indicator in result.indicators)


def test_high_volume_destination_concentration_still_triggers():
    engine = BaselineEngine(history_windows=60, minimum_samples=2)
    normal = make_metric(10, 1000, 0, 0, 2, 2, dest_concentration=0.2)
    engine.update(normal, is_anomalous=False)
    engine.update(normal, is_anomalous=False)

    result = analyze_window(
        make_metric(20, 2000, 0, 0, 2, 1, dest_concentration=1.0, packets=100),
        engine,
    )

    assert "destination concentration anomaly" in result.triggered_indicators


def test_near_idle_post_attack_traffic_recovers_to_normal():
    """After a HIGH_RISK spike, near-idle traffic (< 5 pps) must classify
    as NORMAL rather than being stuck on SUSPICIOUS due to a meaningless
    dest_concentration of 1.0 from 1-2 packets."""
    engine = BaselineEngine(history_windows=60, minimum_samples=10)
    # Simulate 10 warmup windows with low but non-zero dest_concentration
    for _ in range(10):
        engine.update(
            make_metric(0.0, 0.0, 0, 0, 0, 0, dest_concentration=0.0, packets=0),
            is_anomalous=False,
        )

    # Simulate the post-attack window: 1.6 pps, 1 source, 1 dest, conc=1.0
    post_attack = make_metric(
        packets_per_sec=1.6,
        bytes_per_sec=320,
        syn_packets=0,
        connection_attempts=0,
        unique_src_ips=1,
        unique_dst_ips=1,
        dest_concentration=1.0,
        packets=8,
    )
    result = analyze_window(post_attack, engine, minimum_indicators=2)

    dest_indicator = next(
        item for item in result.indicators if item.name == "destination concentration anomaly"
    )
    assert dest_indicator.triggered is False, (
        "Near-idle dest_concentration should not trigger below MIN_MEANINGFUL_PACKETS_PER_SEC"
    )
    assert result.classification == "NORMAL"


def test_non_zero_baseline_low_volume_concentration_suppressed():
    """When baseline has non-zero dest_concentration (e.g. 0.083) but
    current traffic is below the meaningful volume threshold, the
    indicator must be suppressed to allow recovery."""
    engine = BaselineEngine(history_windows=10, minimum_samples=2)
    # Baseline with some non-zero concentration
    engine.update(
        make_metric(8, 1600, 0, 0, 2, 2, dest_concentration=0.083, packets=40),
        is_anomalous=False,
    )
    engine.update(
        make_metric(8, 1600, 0, 0, 2, 2, dest_concentration=0.083, packets=40),
        is_anomalous=False,
    )

    # Post-attack: below MIN_MEANINGFUL_PACKETS_PER_SEC with conc=1.0
    result = analyze_window(
        make_metric(1.6, 320, 0, 0, 1, 1, dest_concentration=1.0, packets=8),
        engine,
        minimum_indicators=1,
    )

    dest = next(i for i in result.indicators if i.name == "destination concentration anomaly")
    assert dest.triggered is False
    assert result.classification == "NORMAL"
