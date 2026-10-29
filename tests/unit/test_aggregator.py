import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.aggregator import Aggregator, SlidingWindowAggregator, compute_window_metrics
from ddos_detector.baseline import BaselineEngine
from ddos_detector.detector import analyze_window
from ddos_detector.feature_extractor import extract_features


def make_raw(ts, src, dst, proto, size, flags=None, sport=None, dport=None):
    return {"timestamp": ts, "src": src, "dst": dst, "protocol": proto, "len": size, "flags": flags, "sport": sport, "dport": dport}


def test_compute_window_metrics_basic():
    raw1 = make_raw(1000.0, "10.0.0.1", "10.0.0.2", 6, 100, flags="S", sport=1234, dport=80)
    raw2 = make_raw(1001.0, "10.0.0.3", "10.0.0.2", 17, 200, flags=None, sport=4000, dport=53)
    p1 = extract_features(raw1)
    p2 = extract_features(raw2)
    wm = compute_window_metrics([p1, p2], window_seconds=5)
    assert wm.packets == 2
    assert wm.packets_per_sec == 2 / 5
    assert wm.tcp_packets == 1
    assert wm.udp_packets == 1
    assert wm.syn_packets == 1
    assert wm.unique_src_ips == 2
    assert wm.unique_dst_ips == 1
    assert wm.avg_packet_size == (100 + 200) / 2
    assert wm.connection_attempts == 1
    assert wm.dst_port_distribution == {80: 1, 53: 1}


def test_aggregator_bounded_history():
    agg = Aggregator(max_history_windows=2)
    packets = []
    for i in range(3):
        packets.append(extract_features(make_raw(float(i), f"10.0.0.{i}", "10.0.0.99", 6, 60, flags="S", sport=5000 + i, dport=80)))
    for pkt in packets:
        agg.add_window([pkt], 5)
    assert len(agg.history) == 2
    assert agg.latest().packets == 1


def test_empty_window_is_safe():
    wm = compute_window_metrics([], window_seconds=5)
    assert wm.packets == 0
    assert wm.bytes == 0
    assert wm.packets_per_sec == 0.0
    assert wm.avg_packet_size == 0.0
    assert wm.unique_src_ips == 0
    assert wm.unique_dst_ips == 0


def test_parser_to_aggregator_counts_only_initial_syn_attempts():
    packets = [
        make_raw(1.0, "10.0.0.1", "10.0.0.2", 6, 60, flags="S"),
        make_raw(1.1, "10.0.0.2", "10.0.0.1", 6, 60, flags="SA"),
        make_raw(1.2, "10.0.0.1", "10.0.0.2", 6, 60, flags="A"),
        make_raw(1.3, "10.0.0.3", "10.0.0.2", 17, 80),
        make_raw(1.4, "10.0.0.4", "10.0.0.2", 1, 100),
        make_raw(1.5, "10.0.0.5", "10.0.0.2", 6, 40),
    ]

    metric = compute_window_metrics([extract_features(packet) for packet in packets], 2)

    assert metric.packets == 6
    assert metric.bytes == 400
    assert metric.packets_per_sec == 3
    assert metric.bytes_per_sec == 200
    assert (metric.tcp_packets, metric.udp_packets, metric.icmp_packets) == (4, 1, 1)
    assert metric.syn_packets == metric.connection_attempts == 1


def test_sliding_windows_include_boundary_crossing_burst_once_per_metric():
    windows = SlidingWindowAggregator(window_seconds=4, slide_seconds=2, started_at=0.0)
    normal = extract_features(make_raw(1.0, "10.0.0.1", "10.0.0.2", 6, 60, flags="S"))
    burst = extract_features(make_raw(3.9, "10.0.0.3", "10.0.0.2", 6, 600, flags="SA"))
    windows.add_packet(normal, received_at=1.0)
    windows.add_packet(burst, received_at=3.9)

    first = windows.pop_ready(4.0)
    assert len(first) == 1
    assert first[0].packets == 2
    assert first[0].syn_packets == 1

    second_packet = extract_features(make_raw(4.1, "10.0.0.4", "10.0.0.2", 17, 80))
    windows.add_packet(second_packet, received_at=4.1)
    second = windows.pop_ready(6.0)
    assert len(second) == 1
    assert second[0].packets == 2
    assert second[0].bytes == 680
    assert second[0].syn_packets == 0


def test_sliding_windows_emit_empty_intervals_and_recovery_metrics():
    windows = SlidingWindowAggregator(window_seconds=4, slide_seconds=2, started_at=0.0)
    empty = windows.pop_ready(6.0)
    assert len(empty) == 2
    assert [metric.packets for metric in empty] == [0, 0]

    normal = extract_features(make_raw(6.1, "10.0.0.1", "10.0.0.2", 17, 100))
    windows.add_packet(normal, received_at=6.1)
    recovered = windows.pop_ready(8.0)
    assert len(recovered) == 1
    assert recovered[0].packets == 1
    assert recovered[0].packets_per_sec == 0.25

    assert windows.pop_ready(10.0)[0].packets == 1


def test_delayed_batch_populates_only_windows_after_its_arrival():
    windows = SlidingWindowAggregator(window_seconds=4, slide_seconds=2, started_at=0.0)
    delayed = extract_features(make_raw(1.0, "10.0.0.9", "10.0.0.2", 17, 100))
    windows.add_packet(delayed, received_at=5.0)

    metrics = windows.pop_ready(8.0)

    assert len(metrics) == 3
    assert [metric.packets for metric in metrics] == [0, 1, 1]


def test_late_packet_batch_is_assigned_to_the_next_open_window():
    windows = SlidingWindowAggregator(window_seconds=4, slide_seconds=2, started_at=0.0)
    assert len(windows.pop_ready(10.0)) == 4
    delayed = extract_features(make_raw(1.0, "10.0.0.9", "10.0.0.2", 17, 100))

    windows.add_packet(delayed, received_at=1.0)

    next_window = windows.pop_ready(12.0)
    assert len(next_window) == 1
    assert next_window[0].packets == 1


def test_anomalous_sliding_window_does_not_contaminate_baseline_and_recovery_does():
    baseline = BaselineEngine(history_windows=5, minimum_samples=1)
    normal_packet = extract_features(make_raw(1.0, "10.0.0.1", "10.0.0.2", 17, 100))
    normal = compute_window_metrics([normal_packet], 4)
    assert baseline.update(normal, is_anomalous=False)

    burst_packets = [
        extract_features(make_raw(2.0 + index, f"10.0.0.{index + 2}", "10.0.0.2", 6, 1000, flags="S"))
        for index in range(20)
    ]
    burst = compute_window_metrics(burst_packets, 4)
    before_burst = baseline.snapshot()
    burst_detection = analyze_window(burst, baseline, allow_provisional=True)
    assert burst_detection.classification in {"SUSPICIOUS", "HIGH_RISK"}
    assert baseline.update(burst, is_anomalous=True) is False
    assert baseline.snapshot().mean == before_burst.mean

    recovery_packet = extract_features(make_raw(8.0, "10.0.0.1", "10.0.0.2", 17, 100))
    recovery = compute_window_metrics([recovery_packet], 4)
    recovery_detection = analyze_window(recovery, baseline, allow_provisional=True)
    assert recovery_detection.classification == "NORMAL"
    assert baseline.update(recovery, is_anomalous=False)
    assert baseline.snapshot().mean["packets_per_sec"] == normal.packets_per_sec
