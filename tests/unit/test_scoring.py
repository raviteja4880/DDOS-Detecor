import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.detector import IndicatorResult
from ddos_detector.scoring import classify_score, score_and_classify, score_indicators


def test_score_is_between_zero_and_one():
    indicators = [
        IndicatorResult("packet-rate anomaly", 4800, 150, 32.0, True, "high"),
        IndicatorResult("SYN-rate anomaly", 2100, 12, 175.0, True, "high"),
        IndicatorResult("distributed-source anomaly", 137, 8, 17.1, True, "high"),
        IndicatorResult("connection-rate anomaly", 1800, 12, 150.0, True, "high"),
    ]
    score = score_indicators(indicators)
    assert 0.0 <= score <= 1.0


def test_classification_thresholds():
    assert classify_score(0.05, {"normal": 0.2, "suspicious": 0.6}) == "NORMAL"
    assert classify_score(0.40, {"normal": 0.2, "suspicious": 0.6}) == "SUSPICIOUS"
    assert classify_score(0.90, {"normal": 0.2, "suspicious": 0.6}) == "HIGH_RISK"


def test_score_and_classify_weights_are_respected():
    indicators = [
        IndicatorResult("packet-rate anomaly", 4800, 150, 32.0, True, "high"),
        IndicatorResult("SYN-rate anomaly", 2100, 12, 175.0, True, "high"),
    ]
    score, cls = score_and_classify(indicators, weights={"packet_rate": 1.0, "syn_rate": 1.0}, thresholds={"normal": 0.2, "suspicious": 0.6})
    assert 0.0 <= score <= 1.0
    assert cls in {"NORMAL", "SUSPICIOUS", "HIGH_RISK"}


def test_high_risk_requires_corroborating_indicators():
    indicators = [
        IndicatorResult("packet-rate anomaly", 1000, 10, 100.0, True, "high"),
        IndicatorResult("byte-rate anomaly", 100000, 1000, 100.0, True, "high"),
    ]
    score, classification = score_and_classify(
        indicators,
        weights={"packet_rate": 1.0, "byte_rate": 1.0},
        thresholds={"normal": 0.2, "suspicious": 0.6},
    )
    assert score >= 0.6
    assert classification == "SUSPICIOUS"


def test_single_indicator_anomalies_remain_suspicious():
    for name in ("packet-rate anomaly", "SYN-rate anomaly"):
        indicators = [IndicatorResult(name, 1000, 10, 100.0, True, "high")]
        _, classification = score_and_classify(
            indicators,
            weights={"packet_rate": 1.0, "syn_rate": 1.0},
            thresholds={"normal": 0.2, "suspicious": 0.6},
        )
        assert classification == "SUSPICIOUS"


def test_score_and_classify_is_deterministic():
    indicators = [
        IndicatorResult("packet-rate anomaly", 500, 10, 50.0, True, "high"),
        IndicatorResult("SYN-rate anomaly", 100, 2, 50.0, True, "high"),
        IndicatorResult("distributed-source anomaly", 20, 2, 10.0, True, "high"),
    ]
    first = score_and_classify(indicators)
    second = score_and_classify(indicators)
    assert first == second


def test_untriggered_indicators_yield_zero_score_and_normal_classification():
    """When indicators are not triggered (e.g. idle/low-volume traffic with zero baseline),
    the score must be 0.0 and classification must be NORMAL, avoiding false SUSPICIOUS
    loops that block recovery."""
    indicators = [
        IndicatorResult("packet-rate anomaly", 1.6, 0.0, 0.0, False, "normal"),
        IndicatorResult("byte-rate anomaly", 204.8, 0.0, 0.0, False, "normal"),
        IndicatorResult("SYN-rate anomaly", 0.0, 0.0, 0.0, False, "normal"),
        IndicatorResult("connection-rate anomaly", 0.0, 0.0, 0.0, False, "normal"),
        IndicatorResult("distributed-source anomaly", 1.0, 0.0, 0.0, False, "normal"),
        IndicatorResult("destination concentration anomaly", 1.0, 0.0, 0.0, False, "normal"),
    ]
    score = score_indicators(indicators)
    assert score == 0.0
    score, classification = score_and_classify(indicators)
    assert score == 0.0
    assert classification == "NORMAL"
