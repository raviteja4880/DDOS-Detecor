from collections import Counter
from collections import deque
from typing import Deque, List

from .feature_extractor import is_tcp_syn_attempt
from .models import PacketFeatures, PacketRecord, WindowMetric


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


def compute_window_metrics(
    packets: List[PacketRecord | PacketFeatures],
    window_seconds: int,
    packet_timestamps: List[float] | None = None,
) -> WindowMetric:
    packets_count = len(packets)
    total_bytes = sum(p.packet_size for p in packets)
    packets_per_sec = packets_count / window_seconds if window_seconds > 0 else 0.0
    bytes_per_sec = total_bytes / window_seconds if window_seconds > 0 else 0.0

    tcp_packets = sum(1 for p in packets if p.protocol == "TCP")
    udp_packets = sum(1 for p in packets if p.protocol == "UDP")
    icmp_packets = sum(1 for p in packets if p.protocol == "ICMP")
    syn_packets = sum(
        1 for p in packets
        if getattr(p, "connection_attempt", None) is True
        or (
            getattr(p, "connection_attempt", None) is None
            and is_tcp_syn_attempt(p.protocol, p.tcp_flags)
        )
    )
    connection_attempts = syn_packets

    unique_src_ips = len(set(p.src_ip for p in packets))
    unique_dst_ips = len(set(p.dst_ip for p in packets))

    dst_ports = [p.dst_port for p in packets if p.dst_port]
    dst_port_distribution = dict(Counter(dst_ports))

    avg_packet_size = (total_bytes / packets_count) if packets_count > 0 else 0.0

    burst_intensity = 0.0
    if packets:
        buckets = {}
        timestamps = packet_timestamps if packet_timestamps is not None else [p.timestamp for p in packets]
        if len(timestamps) != packets_count:
            raise ValueError("packet_timestamps must match the packet count")
        for p, timestamp in zip(packets, timestamps):
            sec = int(timestamp)
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


class SlidingWindowAggregator:
    """Emit rolling metrics on slide boundaries using monotonic arrival times.

    A packet appears at most once in each metric. Adjacent metrics overlap by
    design, so rates from separate sliding metrics must not be summed.
    """

    def __init__(self, window_seconds: int, slide_seconds: int, started_at: float):
        if window_seconds <= 0 or slide_seconds <= 0 or slide_seconds > window_seconds:
            raise ValueError("window_seconds and slide_seconds must be positive, with slide <= window")
        self.window_seconds = window_seconds
        self.slide_seconds = slide_seconds
        self.next_boundary = started_at + window_seconds
        self._packets: Deque[tuple[float, PacketRecord | PacketFeatures]] = deque()
        self._last_received_at = started_at

    def add_packet(self, packet: PacketRecord | PacketFeatures, received_at: float) -> None:
        # Late batches cannot revise emitted metrics; place them in the earliest
        # still-open window while preserving monotonic insertion order.
        received_at = max(received_at, self.next_boundary - self.window_seconds, self._last_received_at)
        self._last_received_at = received_at
        self._packets.append((received_at, packet))

    def seconds_until_next_window(self, now: float) -> float:
        return max(0.0, self.next_boundary - now)

    def pop_ready(self, now: float) -> list[WindowMetric]:
        windows: list[WindowMetric] = []
        while self.next_boundary <= now:
            start = self.next_boundary - self.window_seconds
            entries = [
                (received_at, packet) for received_at, packet in self._packets
                if start <= received_at < self.next_boundary
            ]
            windows.append(compute_window_metrics(
                [packet for _, packet in entries],
                self.window_seconds,
                packet_timestamps=[received_at for received_at, _ in entries],
            ))
            self.next_boundary += self.slide_seconds
            cutoff = self.next_boundary - self.window_seconds
            while self._packets and self._packets[0][0] < cutoff:
                self._packets.popleft()
        return windows
