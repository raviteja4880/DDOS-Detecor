from __future__ import annotations

from typing import Any

from scapy.all import ICMP, IP, TCP, UDP

from .models import PacketRecord


def parse_packet(packet: Any) -> PacketRecord:
    """Parse a Scapy packet or a packet-like dict into a PacketRecord.

    This function is intentionally passive and deterministic. It never sends traffic.
    """
    if isinstance(packet, PacketRecord):
        return packet

    if isinstance(packet, dict):
        if "src_ip" not in packet and "src" not in packet:
            raise ValueError("Malformed packet dict: missing source IP")
        if "dst_ip" not in packet and "dst" not in packet:
            raise ValueError("Malformed packet dict: missing destination IP")

        proto_value = packet.get("protocol", packet.get("proto", "UNKNOWN"))
        if isinstance(proto_value, int):
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            protocol = proto_map.get(proto_value, "UNKNOWN")
        else:
            protocol = str(proto_value).upper() if proto_value else "UNKNOWN"

        src_ip = str(packet.get("src_ip", packet.get("src", "0.0.0.0")))
        dst_ip = str(packet.get("dst_ip", packet.get("dst", "0.0.0.0")))
        src_port = packet.get("src_port", packet.get("sport"))
        dst_port = packet.get("dst_port", packet.get("dport"))
        packet_size = int(packet.get("packet_size", packet.get("len", 0)))
        tcp_flags = packet.get("tcp_flags", packet.get("flags"))
        if tcp_flags is not None:
            tcp_flags = str(tcp_flags)
        return PacketRecord(
            timestamp=float(packet.get("timestamp", 0.0)),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(src_port) if src_port is not None else None,
            dst_port=int(dst_port) if dst_port is not None else None,
            protocol=protocol,
            packet_size=packet_size,
            tcp_flags=tcp_flags,
        )

    if hasattr(packet, "haslayer"):
        if not packet.haslayer(IP):
            raise ValueError("Unsupported packet: missing IPv4 layer")

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        packet_size = int(len(packet))
        src_port = None
        dst_port = None
        protocol = "UNKNOWN"
        tcp_flags = None

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            protocol = "TCP"
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = str(tcp.flags)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            protocol = "UDP"
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        return PacketRecord(
            timestamp=float(getattr(packet, "time", 0.0) or 0.0),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            tcp_flags=tcp_flags,
        )

    raise ValueError("Unsupported packet type")


def parse_raw_packet(raw: bytes) -> PacketRecord:
    """Compatibility wrapper for raw packet bytes. For Phase 1 this remains a scaffold."""
    if isinstance(raw, bytes):
        try:
            from scapy.all import Ether
            packet = Ether(raw)
            return parse_packet(packet)
        except Exception as exc:  # pragma: no cover - placeholder path
            raise ValueError("Unable to parse raw packet bytes") from exc
    return parse_packet(raw)
