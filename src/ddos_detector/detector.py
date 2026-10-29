from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .baseline import BaselineEngine
from .models import WindowMetric


@dataclass
class IndicatorResult:
    name: str
    current: float
    baseline: float
    deviation: float
    triggered: bool
    explanation: str
    threshold: float = 1.25


@dataclass
class DetectionResult:
    indicators: List[IndicatorResult] = field(default_factory=list)
    score: float = 0.0
    classification: str = "NORMAL"
    reason: str = "No anomaly detected"

    @property
    def triggered_indicators(self) -> List[str]:
        return [indicator.name for indicator in self.indicators if indicator.triggered]


class TrafficDetector:
    """Explainable statistical detector for distributed DDoS-like traffic patterns."""

    MIN_MEANINGFUL_PACKETS_PER_SEC = 5.0

    @staticmethod
    def _ratio(current: float, baseline: float) -> float:
        if baseline == 0:
            return float("inf") if current > 0 else 0.0
        return float(current / baseline)

    @staticmethod
    def _is_anomalous(current: float, baseline: float, threshold: float = 1.25) -> bool:
        if baseline == 0:
            return current > 0
        return current > baseline * threshold

    def detect(
        self,
        current: WindowMetric,
        baseline: BaselineEngine,
        minimum_indicators: int = 2,
        allow_provisional: bool = False,
    ) -> DetectionResult:
        """Classify a window only after baseline bootstrap is complete.

        ``allow_provisional`` remains for call compatibility but cannot bypass
        the explicit warm-up state.
        """
        baseline_snapshot = baseline.snapshot()
        indicators: List[IndicatorResult] = []

        metric_map = {
            "packet-rate anomaly": ("packets_per_sec", "packets_per_sec"),
            "byte-rate anomaly": ("bytes_per_sec", "bytes_per_sec"),
            "SYN-rate anomaly": ("syn_packets", "syn_packets"),
            "connection-rate anomaly": ("connection_attempts", "connection_attempts"),
            "distributed-source anomaly": ("unique_src_ips", "unique_src_ips"),
            "destination concentration anomaly": ("dest_concentration", "dest_concentration"),
        }

        def add_indicator(name: str, current_value: float, base_attr: str, *, scale: float = 1.0):
            base_mean, base_std = baseline.get_stat(base_attr)
            baseline_value = base_mean or 0.0
            deviation = self._ratio(current_value / scale, baseline_value / scale)
            triggered = self._is_anomalous(current_value / scale, baseline_value / scale)
            low_volume_zero_baseline = (
                baseline_value == 0.0
                and current.packets_per_sec < self.MIN_MEANINGFUL_PACKETS_PER_SEC
            )
            if low_volume_zero_baseline:
                triggered = False
                deviation = 0.0
            if base_attr in {"syn_packets", "connection_attempts"}:
                current_value = current_value / max(1, current.window_seconds)
                baseline_value = baseline_value / max(1, current.window_seconds)
                deviation = self._ratio(current_value, baseline_value)
                triggered = self._is_anomalous(current_value, baseline_value)
                if low_volume_zero_baseline:
                    triggered = False
                    deviation = 0.0
            if name == "destination concentration anomaly":
                # Concentration is statistically meaningless with very few
                # packets (e.g. 1-2 packets always yield concentration=1.0).
                # Suppress the indicator when traffic is below the minimum
                # volume threshold to prevent perpetual SUSPICIOUS after an
                # attack subsides on an otherwise idle interface.
                low_volume = current.packets_per_sec < self.MIN_MEANINGFUL_PACKETS_PER_SEC
                if low_volume_zero_baseline or low_volume:
                    triggered = False
                    deviation = 0.0
                else:
                    triggered = current.dest_concentration > max(0.15, (baseline_value * 3.0) if baseline_value else 0.15)
                    deviation = current.dest_concentration / max(0.001, baseline_value)
            if name == "distributed-source anomaly" and current.unique_src_ips < 2:
                triggered = False
            explanation = (
                f"{name}: current={current_value:.2f}, baseline={baseline_value:.2f}, "
                f"deviation={deviation:.2f}x"
            )
            indicators.append(
                IndicatorResult(
                    name=name,
                    current=float(current_value),
                    baseline=float(baseline_value),
                    deviation=float(deviation),
                    triggered=bool(triggered),
                    explanation=explanation,
                )
            )

        add_indicator("packet-rate anomaly", current.packets_per_sec, "packets_per_sec")
        add_indicator("byte-rate anomaly", current.bytes_per_sec, "bytes_per_sec")
        add_indicator("SYN-rate anomaly", float(current.syn_packets / max(1, current.window_seconds)), "syn_packets")
        add_indicator("connection-rate anomaly", float(current.connection_attempts / max(1, current.window_seconds)), "connection_attempts")
        add_indicator("distributed-source anomaly", float(current.unique_src_ips), "unique_src_ips")
        add_indicator("destination concentration anomaly", float(current.dest_concentration), "dest_concentration")

        triggered = [indicator for indicator in indicators if indicator.triggered]
        classified = "NORMAL"
        reason = "No anomaly detected; observed traffic remains within learned baseline values."
        if not baseline.is_ready():
            for indicator in indicators:
                indicator.triggered = False
                indicator.explanation += "; baseline warm-up"
            return DetectionResult(
                indicators=indicators,
                classification="BASELINE_WARMUP",
                reason="Baseline warm-up is incomplete; traffic is not classified yet.",
            )
        if triggered and len(triggered) >= max(1, minimum_indicators):
            classified = "SUSPICIOUS"
            reason = "Multiple traffic characteristics exceed the learned baseline."
        strong_names = {
            "SYN-rate anomaly",
            "connection-rate anomaly",
            "distributed-source anomaly",
        }
        corroborated = any(item.name in strong_names for item in triggered)
        if len(triggered) >= max(3, minimum_indicators) and corroborated:
            classified = "HIGH_RISK"
            reason = "Multiple corroborating indicators indicate anomalous attack-like traffic behavior."

        result = DetectionResult(indicators=indicators, classification=classified, reason=reason)
        return result


def analyze_window(
    current: WindowMetric,
    baseline: BaselineEngine,
    minimum_indicators: int = 2,
    allow_provisional: bool = False,
) -> DetectionResult:
    return TrafficDetector().detect(
        current,
        baseline,
        minimum_indicators=minimum_indicators,
        allow_provisional=allow_provisional,
    )
