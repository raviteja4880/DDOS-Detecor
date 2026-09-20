from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "UNKNOWN"  # "TCP", "UDP", "ICMP", etc.
    packet_size: int = 0
    tcp_flags: str | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PacketFeatures:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "UNKNOWN"
    packet_size: int = 0
    tcp_flags: str | None = None
    is_tcp: bool = False
    is_udp: bool = False
    is_icmp: bool = False
    is_syn: bool = False
    connection_attempt: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WindowMetric:
    window_seconds: int
    packets: int
    bytes: int
    packets_per_sec: float
    bytes_per_sec: float
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    syn_packets: int
    connection_attempts: int
    unique_src_ips: int
    unique_dst_ips: int
    dst_port_distribution: Dict[int, int]
    avg_packet_size: float
    burst_intensity: float
    dest_concentration: float
    raw: List[PacketRecord] | None = None
