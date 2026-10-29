from typing import Any

from .models import PacketFeatures, PacketRecord
from .packet_parser import parse_packet


def is_tcp_syn_attempt(protocol: str, tcp_flags: str | None) -> bool:
    """Return whether TCP flags identify an initial SYN without an ACK."""
    flags = str(tcp_flags or "").upper()
    return protocol.upper() == "TCP" and "S" in flags and "A" not in flags


def extract_features(raw: Any) -> PacketFeatures:
    """Convert a packet-like object into a feature object with passive signal flags."""
    packet = parse_packet(raw)
    protocol = packet.protocol.upper()
    flags = str(packet.tcp_flags or "")
    is_tcp = protocol == "TCP"
    is_udp = protocol == "UDP"
    is_icmp = protocol == "ICMP"
    is_syn = is_tcp and is_tcp_syn_attempt(protocol, flags)
    connection_attempt = is_syn

    return PacketFeatures(
        timestamp=packet.timestamp,
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=protocol,
        packet_size=packet.packet_size,
        tcp_flags=packet.tcp_flags,
        is_tcp=is_tcp,
        is_udp=is_udp,
        is_icmp=is_icmp,
        is_syn=is_syn,
        connection_attempt=connection_attempt,
        metadata={"is_syn": is_syn, "connection_attempt": connection_attempt},
    )
