import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import pytest
from scapy.all import Ether, ICMP, IP, TCP, UDP

from ddos_detector.feature_extractor import extract_features
from ddos_detector.packet_parser import parse_packet


def test_parse_ipv4_tcp_syn_packet():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
    result = parse_packet(packet)
    assert result.protocol == "TCP"
    assert result.src_ip == "10.0.0.1"
    assert result.dst_ip == "10.0.0.2"
    assert result.src_port == 12345
    assert result.dst_port == 80
    assert result.tcp_flags == "S"


def test_parse_ipv4_udp_packet():
    packet = Ether() / IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=5353, dport=53)
    result = parse_packet(packet)
    assert result.protocol == "UDP"
    assert result.src_port == 5353
    assert result.dst_port == 53


def test_parse_ipv4_icmp_packet():
    packet = Ether() / IP(src="10.0.0.4", dst="10.0.0.2") / ICMP()
    result = parse_packet(packet)
    assert result.protocol == "ICMP"
    assert result.src_ip == "10.0.0.4"
    assert result.dst_ip == "10.0.0.2"


def test_extract_features_for_syn_and_ack_flags():
    syn = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S")
    syn_ack = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=5000, flags="SA")
    ack = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="A")

    syn_features = extract_features(syn)
    syn_ack_features = extract_features(syn_ack)
    ack_features = extract_features(ack)

    assert syn_features.is_syn is True
    assert syn_features.connection_attempt is True
    assert syn_ack_features.is_syn is False
    assert syn_ack_features.connection_attempt is False
    assert ack_features.is_syn is False
    assert ack_features.connection_attempt is False


def test_parse_packet_rejects_unsupported_packet():
    with pytest.raises(ValueError):
        parse_packet(object())


def test_parse_packet_rejects_malformed_packet():
    with pytest.raises(ValueError):
        parse_packet({"protocol": "TCP", "src_ip": "10.0.0.1"})
