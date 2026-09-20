import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.aggregator import Aggregator, compute_window_metrics
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
