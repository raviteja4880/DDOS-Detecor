import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.feature_extractor import extract_features


def test_extract_features_tcp_syn():
    raw = {
        "timestamp": 1620000000.0,
        "src": "192.168.0.1",
        "dst": "192.168.0.2",
        "sport": 12345,
        "dport": 80,
        "protocol": 6,
        "len": 60,
        "flags": "S",
    }
    pkt = extract_features(raw)
    assert pkt.protocol == "TCP"
    assert pkt.is_syn is True
    assert pkt.connection_attempt is True
    assert pkt.is_tcp is True
    assert pkt.is_udp is False
    assert pkt.is_icmp is False
    assert pkt.src_ip == "192.168.0.1"
    assert pkt.dst_ip == "192.168.0.2"
    assert pkt.packet_size == 60


def test_extract_features_tcp_syn_ack_not_connection_attempt():
    raw = {
        "timestamp": 1620000001.0,
        "src": "192.168.0.3",
        "dst": "192.168.0.4",
        "sport": 443,
        "dport": 12345,
        "protocol": 6,
        "len": 52,
        "flags": "SA",
    }
    pkt = extract_features(raw)
    assert pkt.protocol == "TCP"
    assert pkt.is_syn is False
    assert pkt.connection_attempt is False
