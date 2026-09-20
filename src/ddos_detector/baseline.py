from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Dict, List

from .models import WindowMetric


@dataclass
class BaselineSnapshot:
    mean: Dict[str, float]
    stddev: Dict[str, float]
    sample_count: int


class BaselineEngine:
    """Lightweight bounded baseline for passive monitoring.

    The baseline only learns from non-anomalous windows, which prevents attack traffic
    from being absorbed into the normal baseline.
    """

    def __init__(self, history_windows: int = 60, minimum_samples: int = 10):
        self.history_windows = max(1, int(history_windows))
        self.minimum_samples = max(1, int(minimum_samples))
        self.history: List[WindowMetric] = []

    @staticmethod
    def _stat_values(metrics: List[WindowMetric], attr: str) -> List[float]:
        values: List[float] = []
        for metric in metrics:
            value = getattr(metric, attr, 0.0)
            values.append(float(value))
        return values

    def update(self, metric: WindowMetric, is_anomalous: bool = False) -> bool:
        if is_anomalous:
            return False
        self.history.append(metric)
        if len(self.history) > self.history_windows:
            self.history.pop(0)
        return True

    def snapshot(self) -> BaselineSnapshot:
        attrs = [
            "packets_per_sec",
            "bytes_per_sec",
            "tcp_packets",
            "udp_packets",
            "icmp_packets",
            "syn_packets",
            "connection_attempts",
            "unique_src_ips",
            "unique_dst_ips",
            "avg_packet_size",
        ]
        mean_values: Dict[str, float] = {}
        std_values: Dict[str, float] = {}
        for attr in attrs:
            values = self._stat_values(self.history, attr)
            if not values:
                mean_values[attr] = 0.0
                std_values[attr] = 0.0
                continue
            mean_values[attr] = float(mean(values))
            std_values[attr] = float(pstdev(values)) if len(values) > 1 else 0.0
        return BaselineSnapshot(mean=mean_values, stddev=std_values, sample_count=len(self.history))

    def is_ready(self) -> bool:
        return len(self.history) >= self.minimum_samples

    def get_stat(self, attr: str) -> tuple[float, float]:
        values = self._stat_values(self.history, attr)
        if not values:
            return 0.0, 0.0
        return mean(values), (pstdev(values) if len(values) > 1 else 0.0)

    def reset(self) -> None:
        self.history.clear()
