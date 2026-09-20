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
