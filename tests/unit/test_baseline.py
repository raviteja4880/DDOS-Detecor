import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.baseline import BaselineEngine
from ddos_detector.models import WindowMetric


def make_metric(packets_per_sec, bytes_per_sec, syn_packets, connection_attempts, unique_src_ips, unique_dst_ips, dest_concentration=0.2, avg_packet_size=200.0):
    return WindowMetric(
        window_seconds=5,
        packets=int(packets_per_sec * 5),
        bytes=int(bytes_per_sec * 5),
        packets_per_sec=packets_per_sec,
        bytes_per_sec=bytes_per_sec,
        tcp_packets=int(packets_per_sec * 3),
        udp_packets=int(packets_per_sec * 1),
        icmp_packets=0,
        syn_packets=int(syn_packets),
        connection_attempts=int(connection_attempts),
        unique_src_ips=int(unique_src_ips),
        unique_dst_ips=int(unique_dst_ips),
        dst_port_distribution={80: 10},
        avg_packet_size=avg_packet_size,
        burst_intensity=1.0,
        dest_concentration=dest_concentration,
        raw=None,
    )


def test_baseline_mean_and_stddev():
    baseline = BaselineEngine(history_windows=10, minimum_samples=2)
    baseline.update(make_metric(150, 90000, 10, 12, 8, 3), is_anomalous=False)
    baseline.update(make_metric(160, 92000, 12, 14, 9, 4), is_anomalous=False)
    snapshot = baseline.snapshot()
    assert baseline.is_ready() is True
    assert snapshot.sample_count == 2
    assert snapshot.mean["packets_per_sec"] > 0
    assert snapshot.stddev["packets_per_sec"] >= 0


def test_baseline_empty_is_safe():
    baseline = BaselineEngine(history_windows=5, minimum_samples=2)
    assert baseline.is_ready() is False
    snapshot = baseline.snapshot()
    assert snapshot.sample_count == 0
    assert snapshot.mean["packets_per_sec"] == 0.0


def test_baseline_history_is_bounded():
    baseline = BaselineEngine(history_windows=2, minimum_samples=1)
    for idx in range(5):
        baseline.update(make_metric(100 + idx, 50000 + idx * 1000, 7, 8, 5, 3), is_anomalous=False)
    assert len(baseline.history) == 2


def test_extreme_clean_window_does_not_contaminate_baseline():
    baseline = BaselineEngine(history_windows=5, minimum_samples=2)
    baseline.update(make_metric(100, 50000, 7, 8, 2, 1), is_anomalous=False)
    baseline.update(make_metric(110, 52000, 7, 8, 2, 1), is_anomalous=False)
    assert baseline.update(make_metric(10000, 5000000, 700, 800, 100, 1), is_anomalous=False) is False
    assert len(baseline.history) == 2
    assert baseline.snapshot().mean["packets_per_sec"] < 200
