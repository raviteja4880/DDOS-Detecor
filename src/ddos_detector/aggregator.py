from collections import Counter
from typing import List

from .models import PacketRecord, WindowMetric


class Aggregator:
    """Bounded history aggregator for passive monitoring windows."""

    def __init__(self, max_history_windows: int = 50):
        self.max_history_windows = max_history_windows
        self.history: List[WindowMetric] = []

    def add_window(self, packets: List[PacketRecord], window_seconds: int) -> WindowMetric:
        metrics = compute_window_metrics(packets, window_seconds)
        self.history.append(metrics)
        if len(self.history) > self.max_history_windows:
            self.history.pop(0)
        return metrics

    def latest(self) -> WindowMetric | None:
        return self.history[-1] if self.history else None


def compute_window_metrics(packets: List[PacketRecord], window_seconds: int) -> WindowMetric:
    packets_count = len(packets)
    total_bytes = sum(p.packet_size for p in packets)
    packets_per_sec = packets_count / window_seconds if window_seconds > 0 else 0.0
    bytes_per_sec = total_bytes / window_seconds if window_seconds > 0 else 0.0

    tcp_packets = sum(1 for p in packets if p.protocol == "TCP")
    udp_packets = sum(1 for p in packets if p.protocol == "UDP")
    icmp_packets = sum(1 for p in packets if p.protocol == "ICMP")
    syn_packets = sum(1 for p in packets if str(p.tcp_flags or "").upper().find("S") >= 0)
    connection_attempts = syn_packets

    unique_src_ips = len(set(p.src_ip for p in packets))
    unique_dst_ips = len(set(p.dst_ip for p in packets))

    dst_ports = [p.dst_port for p in packets if p.dst_port]
    dst_port_distribution = dict(Counter(dst_ports))

    avg_packet_size = (total_bytes / packets_count) if packets_count > 0 else 0.0

    burst_intensity = 0.0
    if packets:
        buckets = {}
        for p in packets:
            sec = int(p.timestamp)
            buckets[sec] = buckets.get(sec, 0) + 1
        peak = max(buckets.values()) if buckets else 0
        burst_intensity = (peak / packets_per_sec) if packets_per_sec > 0 else 0.0

    dest_counts = Counter(p.dst_ip for p in packets)
    dest_concentration = 0.0
    if packets_count > 0:
        for count in dest_counts.values():
            share = count / packets_count
            dest_concentration += share * share

    wm = WindowMetric(
        window_seconds=window_seconds,
        packets=packets_count,
        bytes=total_bytes,
        packets_per_sec=packets_per_sec,
        bytes_per_sec=bytes_per_sec,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        icmp_packets=icmp_packets,
        syn_packets=syn_packets,
        connection_attempts=connection_attempts,
        unique_src_ips=unique_src_ips,
        unique_dst_ips=unique_dst_ips,
        dst_port_distribution=dst_port_distribution,
        avg_packet_size=avg_packet_size,
        burst_intensity=burst_intensity,
        dest_concentration=dest_concentration,
        raw=list(packets),
    )
    return wm
