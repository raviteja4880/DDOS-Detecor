from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from statistics import median, mean, pstdev
from typing import Dict, List, Sequence

from .models import WindowMetric


_BOOTSTRAP_OBSERVATION_COUNT = 3
_BOOTSTRAP_RELATIVE_TOLERANCE = 0.25
_BOOTSTRAP_MAD_MULTIPLIER = 6.0
_BOOTSTRAP_FEATURES = (
    "packets_per_sec",
    "bytes_per_sec",
    "tcp_rate",
    "udp_rate",
    "icmp_rate",
    "syn_rate",
    "connection_rate",
    "unique_src_ips",
    "unique_dst_ips",
    "avg_packet_size",
    "burst_intensity",
    "dest_concentration",
)


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
        self._bootstrap_candidates: deque[WindowMetric] = deque(
            maxlen=_BOOTSTRAP_OBSERVATION_COUNT
        )

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
        if self.is_ready() and self._is_extreme_outlier(metric):
            return False
        self._append(metric)
        return True

    def observe_bootstrap(self, metric: WindowMetric) -> bool:
        """Learn only after a bounded, internally consistent bootstrap sample."""
        if self.is_ready():
            return False
        if not self._is_structurally_valid(metric):
            self._bootstrap_candidates.clear()
            return False

        if self.history:
            if not self._matches_reference(metric, self.history):
                return False
            self._append(metric)
            return self.is_ready()

        self._bootstrap_candidates.append(metric)
        if len(self._bootstrap_candidates) < _BOOTSTRAP_OBSERVATION_COUNT:
            return False

        observations = list(self._bootstrap_candidates)
        inliers = self._robust_inliers(observations)
        if len(inliers) >= 2:
            for observation in inliers:
                self._append(observation)
            self._bootstrap_candidates.clear()
            return self.is_ready()

        # Keep the latest two observations so the next valid window can form a
        # new three-window consensus without retaining an unbounded warm-up.
        self._bootstrap_candidates.popleft()
        return False

    @staticmethod
    def _is_structurally_valid(metric: WindowMetric) -> bool:
        if not isinstance(metric, WindowMetric):
            return False

        def finite_nonnegative(value: object) -> bool:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return False
            try:
                return math.isfinite(value) and value >= 0
            except OverflowError:
                return False

        integer_fields = (
            "window_seconds", "packets", "bytes", "tcp_packets", "udp_packets",
            "icmp_packets", "syn_packets", "connection_attempts",
            "unique_src_ips", "unique_dst_ips",
        )
        if any(type(getattr(metric, name, None)) is not int for name in integer_fields):
            return False
        if metric.window_seconds <= 0 or any(
            getattr(metric, name) < 0 for name in integer_fields
        ):
            return False

        float_fields = (
            "packets_per_sec", "bytes_per_sec", "avg_packet_size",
            "burst_intensity", "dest_concentration",
        )
        if any(not finite_nonnegative(getattr(metric, name, None)) for name in float_fields):
            return False

        if not 0.0 <= metric.dest_concentration <= 1.0:
            return False
        if not (
            metric.tcp_packets + metric.udp_packets + metric.icmp_packets
            <= metric.packets
        ):
            return False
        if metric.syn_packets > metric.tcp_packets:
            return False
        if metric.connection_attempts != metric.syn_packets:
            return False
        if metric.unique_src_ips > metric.packets or metric.unique_dst_ips > metric.packets:
            return False
        try:
            expected_packet_rate = metric.packets / metric.window_seconds
            expected_byte_rate = metric.bytes / metric.window_seconds
            expected_average = metric.bytes / metric.packets if metric.packets else 0.0
        except OverflowError:
            return False
        if not math.isclose(metric.packets_per_sec, expected_packet_rate, rel_tol=1e-6, abs_tol=1e-6):
            return False
        if not math.isclose(metric.bytes_per_sec, expected_byte_rate, rel_tol=1e-6, abs_tol=1e-6):
            return False
        if not math.isclose(
            metric.avg_packet_size,
            expected_average,
            rel_tol=1e-6,
            abs_tol=1e-6,
        ):
            return False
        if metric.packets == 0 and any(
            getattr(metric, name) != 0
            for name in (
                "bytes", "tcp_packets", "udp_packets", "icmp_packets",
                "syn_packets", "connection_attempts", "unique_src_ips",
                "unique_dst_ips", "packets_per_sec", "bytes_per_sec",
                "avg_packet_size", "burst_intensity", "dest_concentration",
            )
        ):
            return False

        distribution = metric.dst_port_distribution
        if not isinstance(distribution, dict):
            return False
        if any(
            type(port) is not int or not 1 <= port <= 65535
            or type(count) is not int or count < 0
            for port, count in distribution.items()
        ):
            return False
        if sum(distribution.values()) > metric.packets:
            return False
        if metric.raw is not None and (
            not isinstance(metric.raw, list) or len(metric.raw) != metric.packets
        ):
            return False
        return True

    @staticmethod
    def _features(metric: WindowMetric) -> Dict[str, float]:
        duration = metric.window_seconds
        return {
            "packets_per_sec": float(metric.packets_per_sec),
            "bytes_per_sec": float(metric.bytes_per_sec),
            "tcp_rate": metric.tcp_packets / duration,
            "udp_rate": metric.udp_packets / duration,
            "icmp_rate": metric.icmp_packets / duration,
            "syn_rate": metric.syn_packets / duration,
            "connection_rate": metric.connection_attempts / duration,
            "unique_src_ips": float(metric.unique_src_ips),
            "unique_dst_ips": float(metric.unique_dst_ips),
            "avg_packet_size": float(metric.avg_packet_size),
            "burst_intensity": float(metric.burst_intensity),
            "dest_concentration": float(metric.dest_concentration),
        }

    @staticmethod
    def _robust_inliers(metrics: Sequence[WindowMetric]) -> List[WindowMetric]:
        feature_rows = [BaselineEngine._features(metric) for metric in metrics]
        centers = {
            name: median(row[name] for row in feature_rows)
            for name in _BOOTSTRAP_FEATURES
        }
        deviations = {
            name: median(abs(row[name] - centers[name]) for row in feature_rows)
            for name in _BOOTSTRAP_FEATURES
        }
        limits = {
            name: max(
                _BOOTSTRAP_MAD_MULTIPLIER * deviations[name],
                _BOOTSTRAP_RELATIVE_TOLERANCE * max(abs(centers[name]), 1.0),
            )
            for name in _BOOTSTRAP_FEATURES
        }
        return [
            metric
            for metric, row in zip(metrics, feature_rows)
            if all(
                abs(row[name] - centers[name]) <= limits[name]
                for name in _BOOTSTRAP_FEATURES
            )
        ]

    @classmethod
    def _matches_reference(
        cls, metric: WindowMetric, reference: Sequence[WindowMetric]
    ) -> bool:
        return len(cls._robust_inliers([*reference, metric])) == len(reference) + 1

    def _append(self, metric: WindowMetric) -> None:
        self.history.append(metric)
        if len(self.history) > self.history_windows:
            self.history.pop(0)

    def _is_extreme_outlier(self, metric: WindowMetric) -> bool:
        attrs = ("packets_per_sec", "bytes_per_sec", "syn_packets", "connection_attempts", "unique_src_ips")
        snapshot = self.snapshot()
        for attr in attrs:
            current = float(getattr(metric, attr, 0.0))
            mean_value = snapshot.mean.get(attr, 0.0)
            std_value = snapshot.stddev.get(attr, 0.0)
            limit = max(mean_value * 4.0, mean_value + max(3.0 * std_value, 1.0))
            if mean_value > 0 and current > limit:
                return True
        return False

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
        self._bootstrap_candidates.clear()
