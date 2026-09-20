from __future__ import annotations

from typing import Dict, Iterable, List

from .detector import IndicatorResult


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def normalize_indicator(indicator: IndicatorResult) -> float:
    if indicator.baseline <= 0:
        if indicator.current > 0:
            return 1.0
        return 0.0
    ratio = indicator.current / indicator.baseline
    if ratio <= 1.0:
        return 0.0
    signal = (ratio - 1.0) / 10.0
    return clamp(signal)


def score_indicators(indicators: Iterable[IndicatorResult], weights: Dict[str, float] | None = None) -> float:
    indicator_list = list(indicators)
    if not indicator_list:
        return 0.0
    if weights is None:
        weights = {
            "syn_rate": 1.0,
            "packet_rate": 0.8,
            "distributed_source": 1.0,
            "connection_rate": 0.7,
            "dest_concentration": 0.5,
        }

    weighted_total = 0.0
    total_weight = 0.0
    for indicator in indicator_list:
        key = indicator.name.lower()
        key = key.replace(" anomaly", "")
        key = key.replace("-", "_")
        key = key.replace(" ", "_")
        key = key.replace("/", "_")
        weight = weights.get(key, 0.5)
        score = normalize_indicator(indicator)
        weighted_total += weight * score
        total_weight += weight
    if total_weight == 0:
        return 0.0
    score = weighted_total / total_weight
    return clamp(score)


def classify_score(score: float, thresholds: Dict[str, float] | None = None) -> str:
    if thresholds is None:
        thresholds = {"normal": 0.2, "suspicious": 0.6}
    if score < float(thresholds.get("normal", 0.2)):
        return "NORMAL"
    if score < float(thresholds.get("suspicious", 0.6)):
        return "SUSPICIOUS"
    return "HIGH_RISK"


def score_and_classify(indicators: Iterable[IndicatorResult], weights: Dict[str, float] | None = None, thresholds: Dict[str, float] | None = None) -> tuple[float, str]:
    score = score_indicators(indicators, weights=weights)
    classification = classify_score(score, thresholds=thresholds)
    return score, classification
