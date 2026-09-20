from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

logger = logging.getLogger("ddos_detector")
ALERT_HISTORY: List[Dict[str, Any]] = []
MAX_ALERT_HISTORY = 100


def build_alert(classification: str, score: float, reasons: Iterable[str], current_metrics: Dict[str, Any] | None = None, baseline: Dict[str, Any] | None = None) -> Dict[str, Any]:
    metrics = current_metrics or {}
    baseline_data = baseline or {}
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "classification": str(classification).upper(),
        "score": float(score),
        "severity": "HIGH" if str(classification).upper() in {"HIGH_RISK"} else "MEDIUM" if str(classification).upper() == "SUSPICIOUS" else "LOW",
        "reasons": list(reasons),
        "current_metrics": metrics,
        "baseline": baseline_data,
    }
    return alert


def record_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    ALERT_HISTORY.append(alert)
    if len(ALERT_HISTORY) > MAX_ALERT_HISTORY:
        ALERT_HISTORY.pop(0)
    return alert


def emit_console_alert(alert: Dict[str, Any]) -> None:
    classification = str(alert.get("classification", "NORMAL")).upper()
    score = float(alert.get("score", 0.0))
    reasons = alert.get("reasons", [])
    print(f"[{classification}] score={score}")
    for reason in reasons:
        print(f"- {reason}")


def maybe_emit_alert(classification: str, score: float, reasons: List[str], current_metrics: Dict[str, Any] | None = None, baseline: Dict[str, Any] | None = None) -> Dict[str, Any] | None:
    normalized = str(classification).upper()
    if normalized not in {"SUSPICIOUS", "HIGH_RISK"}:
        return None
    alert = build_alert(normalized, score, reasons, current_metrics=current_metrics, baseline=baseline)
    emit_console_alert(alert)
    logger.info(json.dumps(alert, sort_keys=True))
    record_alert(alert)
    return alert
