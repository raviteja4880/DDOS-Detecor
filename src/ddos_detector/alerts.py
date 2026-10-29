from __future__ import annotations

import json
import logging
from html import escape
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

logger = logging.getLogger("ddos_detector")
ALERT_HISTORY: List[Dict[str, Any]] = []
MAX_ALERT_HISTORY = 100


def build_alert(
    classification: str,
    score: float,
    reasons: Iterable[str],
    current_metrics: Dict[str, Any] | None = None,
    baseline: Dict[str, Any] | None = None,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
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
    if context:
        alert["context"] = context
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


from contextlib import contextmanager
import os
import smtplib
import tempfile
import threading
import time
from email.message import EmailMessage
from typing import Callable

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]

MAX_PERSISTED_INCIDENTS = 100
MAX_STATE_FILE_BYTES = 65536
IN_FLIGHT_LEASE_SECONDS = 30.0
MAX_INCIDENT_AGE_SECONDS = 86400.0

ALERT_COOLDOWN_LOCK = threading.RLock()
EMAIL_IN_FLIGHT: set[str] = set()
_SYNCING_MEMORY = False


def _state_file_path(alert_cfg: Dict[str, Any] | None = None) -> str:
    if isinstance(alert_cfg, dict):
        direct = alert_cfg.get("state_file")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        email_cfg = alert_cfg.get("email")
        if isinstance(email_cfg, dict):
            nested = email_cfg.get("state_file")
            if isinstance(nested, str) and nested.strip():
                return nested.strip()
    env_path = os.environ.get("DDOS_DETECTOR_ALERT_STATE_FILE", "").strip()
    if env_path:
        return env_path
    base_dir = os.environ.get("DDOS_DETECTOR_LOCK_DIR", "").strip() or tempfile.gettempdir()
    return os.path.join(base_dir, "ddos_detector_alert_state.json")


@contextmanager
def _alert_state_file_lock(state_path: str):
    with ALERT_COOLDOWN_LOCK:
        if fcntl is None:
            yield
            return
        lock_path = f"{state_path}.lock"
        lock_fd: int | None = None
        try:
            parent = os.path.dirname(os.path.abspath(lock_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except OSError as exc:
            logger.debug("Alert state lock unavailable for %s: %s", lock_path, exc)
            if lock_fd is not None:
                try:
                    os.close(lock_fd)
                except OSError:
                    pass
                lock_fd = None
        try:
            yield
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(lock_fd)
                except OSError:
                    pass


def _read_state_file_unlocked(state_path: str, now: float | None = None) -> Dict[str, Any]:
    empty: Dict[str, Any] = {"incidents": {}, "last_sent": {}}
    if not state_path or not os.path.isfile(state_path):
        return empty
    try:
        size = os.path.getsize(state_path)
        if size <= 0:
            return empty
        if size > MAX_STATE_FILE_BYTES:
            logger.warning("Alert state file %s exceeds %d bytes; ignoring persisted state", state_path, MAX_STATE_FILE_BYTES)
            return empty
        with open(state_path, "r", encoding="utf-8") as state_file:
            payload = json.load(state_file)
    except (OSError, ValueError, TypeError) as exc:
        logger.warning("Corrupt or unreadable alert state file %s (%s); starting clean", state_path, exc)
        return empty

    if not isinstance(payload, dict):
        logger.warning("Invalid alert state root in %s; starting clean", state_path)
        return empty

    raw_incidents = payload.get("incidents")
    raw_last_sent = payload.get("last_sent")
    if not isinstance(raw_incidents, dict) or not isinstance(raw_last_sent, dict):
        logger.warning("Malformed alert state structure in %s; starting clean", state_path)
        return empty

    incidents: Dict[str, Dict[str, Any]] = {}
    for key, entry in raw_incidents.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            continue
        try:
            updated_at = float(entry.get("updated_at", 0.0) or 0.0)
            in_flight_until = float(entry.get("in_flight_until", 0.0) or 0.0)
            normal_windows = max(0, int(entry.get("normal_windows", 0) or 0))
        except (TypeError, ValueError, OverflowError):
            continue
        if now is not None and updated_at > 0.0 and now >= updated_at and (now - updated_at) > MAX_INCIDENT_AGE_SECONDS:
            continue
        raw_targets = entry.get("targets") or []
        if not isinstance(raw_targets, (list, tuple, set)):
            raw_targets = []
        incidents[key] = {
            "interface": str(entry.get("interface") or "unknown"),
            "notified": bool(entry.get("notified", False)),
            "normal_windows": normal_windows,
            "targets": {str(item) for item in raw_targets if item is not None},
            "in_flight_until": in_flight_until if in_flight_until > 0.0 else 0.0,
            "updated_at": updated_at,
        }

    if len(incidents) > MAX_PERSISTED_INCIDENTS:
        ordered_keys = sorted(
            incidents,
            key=lambda k: float(incidents[k].get("updated_at", 0.0) or 0.0),
        )
        for stale_key in ordered_keys[: len(incidents) - MAX_PERSISTED_INCIDENTS]:
            incidents.pop(stale_key, None)

    last_sent: Dict[str, float] = {}
    for key, ts in raw_last_sent.items():
        if not isinstance(key, str) or isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        ts_val = float(ts)
        if now is not None and ts_val > 0.0 and now >= ts_val and (now - ts_val) > MAX_INCIDENT_AGE_SECONDS:
            continue
        last_sent[key] = ts_val

    if len(last_sent) > MAX_PERSISTED_INCIDENTS:
        ordered_sent = sorted(last_sent, key=lambda k: last_sent[k])
        for stale_key in ordered_sent[: len(last_sent) - MAX_PERSISTED_INCIDENTS]:
            last_sent.pop(stale_key, None)

    return {"incidents": incidents, "last_sent": last_sent}


def _write_state_file_unlocked(
    state_path: str,
    incidents: Dict[str, Dict[str, Any]],
    last_sent: Dict[str, float],
) -> None:
    if not state_path:
        return
    serializable_incidents: Dict[str, Dict[str, Any]] = {}
    items = list(incidents.items())
    if len(items) > MAX_PERSISTED_INCIDENTS:
        items = sorted(
            items,
            key=lambda kv: float((kv[1] or {}).get("updated_at", 0.0) or 0.0),
        )[-MAX_PERSISTED_INCIDENTS:]
    for key, state in items:
        if not isinstance(key, str) or not isinstance(state, dict):
            continue
        targets = state.get("targets") or set()
        serializable_incidents[key] = {
            "interface": str(state.get("interface") or "unknown"),
            "notified": bool(state.get("notified", False)),
            "normal_windows": max(0, int(state.get("normal_windows", 0) or 0)),
            "targets": sorted(str(item) for item in targets if item is not None),
            "in_flight_until": float(state.get("in_flight_until", 0.0) or 0.0),
            "updated_at": float(state.get("updated_at", 0.0) or 0.0),
        }

    serializable_last_sent: Dict[str, float] = {}
    sent_items = [
        (k, float(v))
        for k, v in last_sent.items()
        if isinstance(k, str) and not isinstance(v, bool) and isinstance(v, (int, float))
    ]
    if len(sent_items) > MAX_PERSISTED_INCIDENTS:
        sent_items = sorted(sent_items, key=lambda kv: kv[1])[-MAX_PERSISTED_INCIDENTS:]
    for key, ts_val in sent_items:
        serializable_last_sent[key] = ts_val

    payload = {
        "version": 1,
        "incidents": serializable_incidents,
        "last_sent": serializable_last_sent,
    }
    tmp_path: str | None = None
    try:
        parent = os.path.dirname(os.path.abspath(state_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".ddos_alert_state_",
            suffix=".tmp",
            dir=parent or None,
        )
        try:
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(payload, tmp_file, sort_keys=True)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.replace(tmp_path, state_path)
        try:
            os.chmod(state_path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        logger.debug("Unable to persist alert state to %s: %s", state_path, exc)
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


class _SyncedStateDict(dict):
    """Dictionary wrapper keeping in-memory alert state and local state file aligned."""

    def _sync_Write(self) -> None:
        if _SYNCING_MEMORY:
            return
        state_path = _state_file_path()
        with _alert_state_file_lock(state_path):
            _write_state_file_unlocked(state_path, INCIDENT_STATE, ALERT_LAST_SENT)

    def clear(self) -> None:
        super().clear()
        self._sync_Write()

    def __setitem__(self, key, value) -> None:
        super().__setitem__(key, value)
        self._sync_Write()

    def __delitem__(self, key) -> None:
        super().__delitem__(key)
        self._sync_Write()

    def pop(self, key, *args):
        result = super().pop(key, *args)
        self._sync_Write()
        return result

    def update(self, *args, **kwargs) -> None:
        super().update(*args, **kwargs)
        self._sync_Write()


# Incident-scoped cooldown and state stores synchronized with bounded local file state.
ALERT_LAST_SENT: Dict[str, float] = _SyncedStateDict()
INCIDENT_STATE: Dict[str, Dict[str, Any]] = _SyncedStateDict()


def _sync_from_disk_unlocked(state_path: str, now: float | None = None) -> None:
    global _SYNCING_MEMORY
    loaded = _read_state_file_unlocked(state_path, now=now)
    _SYNCING_MEMORY = True
    try:
        dict.clear(INCIDENT_STATE)
        dict.update(INCIDENT_STATE, loaded["incidents"])
        dict.clear(ALERT_LAST_SENT)
        dict.update(ALERT_LAST_SENT, loaded["last_sent"])
    finally:
        _SYNCING_MEMORY = False


def reset_memory_state_for_restart() -> None:
    """Clear only in-process memory without erasing the persisted state file."""
    global _SYNCING_MEMORY
    with ALERT_COOLDOWN_LOCK:
        _SYNCING_MEMORY = True
        try:
            dict.clear(INCIDENT_STATE)
            dict.clear(ALERT_LAST_SENT)
            EMAIL_IN_FLIGHT.clear()
        finally:
            _SYNCING_MEMORY = False


def _incident_data(alert: Dict[str, Any]) -> Dict[str, Any]:
    current = alert.get("current_metrics", {})
    baseline = alert.get("baseline", {})
    context = alert.get("context", {})
    classification = str(alert.get("classification", "NORMAL"))
    labels = {
        "packet-rate anomaly": "Packet rate",
        "byte-rate anomaly": "Byte rate",
        "SYN-rate anomaly": "TCP SYN rate",
        "connection-rate anomaly": "Connection rate",
        "distributed-source anomaly": "Distributed source behavior",
        "destination concentration anomaly": "Destination concentration",
    }
    metrics = [
        ("Packet rate", "packets_per_sec", "packets/sec"),
        ("Byte rate", "bytes_per_sec", "bytes/sec"),
        ("TCP SYN rate", "syn_rate", "SYN/sec"),
        ("Connection rate", "connection_rate", "connections/sec"),
        ("Unique sources", "unique_src_ips", "sources"),
        ("Destination concentration", "dest_concentration", "share"),
        ("Average packet size", "avg_packet_size", "bytes"),
        ("Burst intensity", "burst_intensity", "ratio"),
    ]
    comparisons = []
    for label, key, unit in metrics:
        if key not in current and key not in baseline:
            continue
        current_value = current.get(key)
        baseline_value = baseline.get(key)
        if key == "bytes_per_sec":
            current_display = f"{float(current_value or 0) / 1024:.2f} KB/s"
            baseline_display = f"{float(baseline_value or 0) / 1024:.2f} KB/s"
        elif key == "dest_concentration":
            current_display = f"{float(current_value or 0) * 100:.2f}%"
            baseline_display = f"{float(baseline_value or 0) * 100:.2f}%"
        else:
            current_display = f"{current_value if current_value is not None else 'Unavailable'} {unit}"
            baseline_display = f"{baseline_value if baseline_value is not None else 'Unavailable'} {unit}"
        comparisons.append({"label": label, "current": current_display, "baseline": baseline_display})
    source_ips = context.get("source_ips") or ["Unavailable"]
    if isinstance(source_ips, dict):
        source_lines = [f"{ip} ({count})" for ip, count in source_ips.items()]
    else:
        source_lines = [str(item) for item in source_ips]
    return {
        "classification": classification,
        "score": float(alert.get("score", 0.0)),
        "severity": alert.get("severity", "Unavailable"),
        "timestamp": alert.get("timestamp", "Unavailable"),
        "reasons": [labels.get(str(reason), str(reason)) for reason in alert.get("reasons", [])],
        "comparisons": comparisons,
        "sources": source_lines,
        "targets": [str(item) for item in (context.get("target_ips") or ["Unavailable"])],
        "ports": [str(item) for item in (context.get("target_ports") or ["Unavailable"])],
        "interface": context.get("interface") or "Unavailable",
        "mitigation": context.get("mitigation", {}) or {},
    }


def format_alert_email(alert: Dict[str, Any]) -> str:
    """Render the plain-text fallback for a contextual incident notification."""
    data = _incident_data(alert)
    mitigation = data["mitigation"]
    lines = [
        "DDOS DETECTION SYSTEM",
        "Security Incident Alert",
        "",
        "WHAT IS HAPPENING?",
        "Abnormal, DDoS-like traffic was detected.",
        "",
        "INCIDENT SUMMARY",
        f"Classification : {data['classification']}",
        f"Risk Score    : {data['score']:.2f}",
        f"Severity      : {data['severity']}",
        f"Detected At   : {data['timestamp']}",
        "",
        "WHY DID IT TRIGGER?",
    ]
    lines.extend(f"- {item['label']}: current {item['current']} vs baseline {item['baseline']}" for item in data["comparisons"])
    lines.extend(
        [
            "",
            "WHERE IS THE TRAFFIC COMING FROM?",
            *[f"- Source IP: {source}" for source in data["sources"]],
            f"- Target IP: {', '.join(data['targets'])}",
            f"- Target port: {', '.join(data['ports'])}",
            f"- Interface: {data['interface']}",
            "",
            "WHAT DID THE SYSTEM DO?",
            f"- Mitigation configured: {'YES' if mitigation.get('enabled') else 'NO'}",
            f"- Source-IP blocking configured: {'YES' if mitigation.get('auto_block_sources') else 'NO'}",
            f"- Mechanism: {mitigation.get('mechanism', 'Unavailable')}",
            f"- Maximum sources blocked: {mitigation.get('max_auto_block_sources', 'Unavailable')} per detection window",
            f"- Rule lifetime: {mitigation.get('rule_ttl_seconds', 'Unavailable')} seconds (TTL)",
            f"- Applied rules: {', '.join(map(str, mitigation.get('applied_rules', []))) if mitigation.get('applied_rules') else 'None reported'}",
            f"- Decision: {mitigation.get('decision', 'Detected but not automatically blocked')}",
            f"- Decision reason: {mitigation.get('reason', 'No automatic mitigation decision was recorded.')}",
            f"- Shared/NAT ambiguity: {'YES' if mitigation.get('shared_nat_ambiguous') else 'NO'}",
            "",
            "Triggered indicators: " + ", ".join(data["reasons"]),
            "This notification was generated automatically by the DDoS detection engine.",
        ]
    )
    return "\n".join(lines)


def format_alert_email_html(alert: Dict[str, Any]) -> str:
    """Render a professional HTML notification with no credentials or secrets."""
    data = _incident_data(alert)
    mitigation = data["mitigation"]
    esc = lambda value: escape(str(value))
    rows = "".join(
        f"<tr><td>{esc(item['label'])}</td><td>{esc(item['current'])}</td><td>{esc(item['baseline'])}</td></tr>"
        for item in data["comparisons"]
    )
    reasons = "".join(f"<li>{esc(reason)}</li>" for reason in data["reasons"])
    sources = "".join(f"<li><code>{esc(source)}</code></li>" for source in data["sources"])
    applied = mitigation.get("applied_rules") or []
    status = "Applied" if applied else ("Enabled; no applied rule reported" if mitigation.get("enabled") else "Disabled")
    return f"""<!doctype html>
<html><body style="margin:0;background:#f3f4f6;font-family:Arial,sans-serif;color:#172033">
<div style="max-width:720px;margin:24px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px #0001">
<div style="background:#8b0000;color:#fff;padding:24px"><div style="font-size:13px;letter-spacing:1px">DDOS DETECTION SYSTEM</div>
<h1 style="margin:10px 0 0;font-size:26px">HIGH RISK TRAFFIC DETECTED</h1><p>Abnormal, DDoS-like traffic was detected.</p></div>
<div style="padding:24px"><h2>Incident details</h2>
<p><b>Classification:</b> {esc(data["classification"])} &nbsp; <b>Risk score:</b> {data["score"]:.2f}<br>
<b>Severity:</b> {esc(data["severity"])} &nbsp; <b>Detected at:</b> {esc(data["timestamp"])}</p>
<h2>Why did it trigger?</h2><ul>{reasons}</ul>
<table style="border-collapse:collapse;width:100%"><tr style="background:#eef2f7"><th align="left">Indicator</th><th align="left">Current</th><th align="left">Baseline</th></tr>{rows}</table>
<h2>Where is the traffic coming from?</h2><p><b>Source IP(s)</b></p><ul>{sources}</ul>
<p><b>Target IP:</b> {esc(", ".join(data["targets"]))}<br><b>Target port:</b> {esc(", ".join(data["ports"]))}<br><b>Interface:</b> {esc(data["interface"])}</p>
<h2>What did the system do?</h2><p><b>Mitigation:</b> {esc(status)}<br>
<b>Source-IP blocking:</b> {"Enabled" if mitigation.get("auto_block_sources") else "Disabled"}<br>
<b>Mechanism:</b> {esc(mitigation.get("mechanism", "Unavailable"))}<br>
<b>Maximum sources blocked:</b> {esc(mitigation.get("max_auto_block_sources", "Unavailable"))} per detection window<br>
<b>Rule TTL:</b> {esc(mitigation.get("rule_ttl_seconds", "Unavailable"))} seconds<br>
<b>Applied rule(s):</b> {esc(", ".join(map(str, applied)) if applied else "None reported")}<br>
<b>Decision:</b> {esc(mitigation.get("decision", "Detected but not automatically blocked"))}<br>
<b>Decision reason:</b> {esc(mitigation.get("reason", "No automatic mitigation decision was recorded."))}<br>
<b>Shared/NAT ambiguity:</b> {"YES" if mitigation.get("shared_nat_ambiguous") else "NO"}</p>
<p style="font-size:12px;color:#657184">This notification was generated automatically by the DDoS detection engine.</p>
</div></div></body></html>"""


def _send_email_via_smtp(alert: Dict[str, Any], smtp_config: Dict[str, Any]) -> Dict[str, Any]:
    host = smtp_config.get("host") or os.environ.get("SMTP_HOST")
    port = int(smtp_config.get("port") or os.environ.get("SMTP_PORT", 25))
    user = smtp_config.get("user") or os.environ.get("SMTP_USER")
    password = smtp_config.get("password") or os.environ.get("SMTP_PASSWORD")
    from_addr = smtp_config.get("from") or os.environ.get("SMTP_FROM")
    to_addrs = smtp_config.get("to") or os.environ.get("SMTP_TO")
    if not host or not from_addr or not to_addrs:
        logger.warning("SMTP not configured properly; skipping email send")
        return {"attempted": False, "configuration_valid": False, "delivered": False, "status": "not_requested", "reason": "missing_configuration"}
    if isinstance(to_addrs, str):
        to_addrs = [addr.strip() for addr in to_addrs.split(",") if addr.strip()]

    msg = EmailMessage()
    msg["Subject"] = f"DDoS Detector Alert: {alert.get('classification')} score={alert.get('score'):.2f}"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(format_alert_email(alert))
    msg.add_alternative(format_alert_email_html(alert), subtype="html")

    try:
        if port == 465:
            smtp = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            smtp = smtplib.SMTP(host, port, timeout=10)
        smtp.ehlo()
        if port != 465:
            smtp.starttls()
            smtp.ehlo()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg)
        smtp.quit()
        logger.info("Alert email sent via SMTP to %s", to_addrs)
        return {"attempted": True, "configuration_valid": True, "delivered": True, "status": "accepted", "reason": "accepted"}
    except Exception as exc:
        logger.exception("Failed to send alert email: %s", exc)
        return {"attempted": True, "configuration_valid": True, "delivered": False, "status": "send_failed", "reason": "delivery_failure"}


def _incident_key(context: Dict[str, Any] | None) -> str:
    """Build a stable identity from destination context, excluding volatile alert data."""
    context = context or {}
    interface = str(context.get("interface") or "unknown")
    targets = tuple(sorted(str(item) for item in (context.get("target_ips") or [])))
    return json.dumps({"interface": interface, "target_ips": targets}, sort_keys=True)


def mark_normal_window(
    interface: str,
    required_windows: int = 2,
    alert_cfg: Dict[str, Any] | None = None,
) -> None:
    """Re-arm incidents after consecutive normal windows on an interface."""
    required = max(1, int(required_windows))
    state_path = _state_file_path(alert_cfg)
    with _alert_state_file_lock(state_path):
        _sync_from_disk_unlocked(state_path)
        changed = False
        for key, state in list(INCIDENT_STATE.items()):
            if state.get("interface") != str(interface):
                continue
            state["normal_windows"] = int(state.get("normal_windows", 0)) + 1
            changed = True
            if state["normal_windows"] < required:
                continue
            dict.pop(INCIDENT_STATE, key, None)
            dict.pop(ALERT_LAST_SENT, key, None)
            logger.info("INCIDENT_RECOVERED incident=%s", key)
            logger.info("INCIDENT_REARMED incident=%s", key)
        if changed:
            _write_state_file_unlocked(state_path, INCIDENT_STATE, ALERT_LAST_SENT)


def _send_email_via_brevo(alert: Dict[str, Any], brevo_config: Dict[str, Any]) -> Dict[str, Any]:
    # Use requests to post to Brevo transactional smtp endpoint
    try:
        import requests
    except Exception:
        logger.error("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=unavailable EMAIL_DELIVERED=false reason=requests_dependency_missing")
        return {"attempted": False, "configuration_valid": False, "delivered": False, "status": "unavailable", "reason": "requests_dependency_missing"}

    api_key = brevo_config.get("api_key") or os.environ.get("BREVO_API_KEY")
    sender_email = brevo_config.get("from") or os.environ.get("BREVO_SENDER_EMAIL")
    sender_name = brevo_config.get("from_name") or os.environ.get("BREVO_SENDER_NAME")
    to_addr = brevo_config.get("to") or os.environ.get("BREVO_ALERT_RECIPIENT")
    if not api_key or not sender_email or not to_addr:
        missing = [
            name for name, value in (
                ("BREVO_API_KEY", api_key),
                ("BREVO_SENDER_EMAIL", sender_email),
                ("BREVO_ALERT_RECIPIENT", to_addr),
            ) if not value
        ]
        logger.error(
            "EMAIL_ATTEMPTED=false BREVO_RESPONSE_STATUS=not_requested EMAIL_DELIVERED=false "
            "EMAIL_CONFIGURATION_VALID=false reason=missing_configuration missing=%s",
            ",".join(missing),
        )
        return {"attempted": False, "configuration_valid": False, "delivered": False, "status": "not_requested", "reason": "missing_configuration"}
    if isinstance(to_addr, str):
        to_addr = [addr.strip() for addr in to_addr.split(",") if addr.strip()]

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {"accept": "application/json", "content-type": "application/json", "api-key": api_key}
    sender = {"email": sender_email, "name": sender_name or "ddos-detector"}
    to_list = [{"email": addr} for addr in to_addr]
    data = {
        "sender": sender,
        "to": to_list,
        "subject": f"DDoS Detector Alert: {alert.get('classification')} score={alert.get('score'):.2f}",
        "textContent": format_alert_email(alert),
        "htmlContent": format_alert_email_html(alert),
    }
    try:
        resp = requests.post(url, json=data, headers=headers, timeout=10)
        if resp.status_code >= 200 and resp.status_code < 300:
            logger.info("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=%s EMAIL_DELIVERED=true reason=accepted", resp.status_code)
            return {"attempted": True, "configuration_valid": True, "delivered": True, "status": resp.status_code, "reason": "accepted"}
        elif resp.status_code == 401:
            logger.error("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=401 EMAIL_DELIVERED=false reason=authentication_failed")
        elif resp.status_code == 403:
            logger.error("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=403 EMAIL_DELIVERED=false reason=sender_or_ip_forbidden")
        elif resp.status_code == 429:
            logger.warning("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=429 EMAIL_DELIVERED=false reason=rate_limited")
        elif 400 <= resp.status_code < 500:
            logger.error("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=%s EMAIL_DELIVERED=false reason=client_rejected", resp.status_code)
        elif 500 <= resp.status_code:
            logger.error("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=%s EMAIL_DELIVERED=false reason=brevo_server_error", resp.status_code)
        else:
            logger.error("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=%s EMAIL_DELIVERED=false reason=unexpected_status", resp.status_code)
        return {"attempted": True, "configuration_valid": True, "delivered": False, "status": resp.status_code, "reason": "request_rejected"}
    except requests.Timeout:
        logger.warning("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=timeout EMAIL_DELIVERED=false reason=timeout; monitoring continues")
        return {"attempted": True, "configuration_valid": True, "delivered": False, "status": "timeout", "reason": "timeout"}
    except requests.RequestException:
        logger.warning("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=network_error EMAIL_DELIVERED=false reason=network_failure; monitoring continues")
        return {"attempted": True, "configuration_valid": True, "delivered": False, "status": "network_error", "reason": "network_failure"}
    except (AttributeError, TypeError, ValueError):
        logger.warning("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=invalid_response EMAIL_DELIVERED=false reason=invalid_response; monitoring continues")
        return {"attempted": True, "configuration_valid": True, "delivered": False, "status": "invalid_response", "reason": "invalid_response"}
    except Exception:
        logger.warning("EMAIL_ATTEMPTED=true BREVO_RESPONSE_STATUS=unknown_error EMAIL_DELIVERED=false reason=delivery_failure; monitoring continues")
        return {"attempted": True, "configuration_valid": True, "delivered": False, "status": "unknown_error", "reason": "delivery_failure"}


def maybe_emit_alert(
    classification: str,
    score: float,
    reasons: List[str],
    current_metrics: Dict[str, Any] | None = None,
    baseline: Dict[str, Any] | None = None,
    alert_cfg: Dict[str, Any] | None = None,
    context: Dict[str, Any] | None = None,
    clock: Callable[[], float] | None = None,
) -> Dict[str, Any] | None:
    """Emit an alert to console/log and optionally via SMTP or Brevo.

    alert_cfg is an optional configuration dict controlling email provider (smtp/brevo) and cooldown behavior.
    """
    normalized = str(classification).upper()
    if normalized not in {"SUSPICIOUS", "HIGH_RISK"}:
        return None
    alert = build_alert(normalized, score, reasons, current_metrics=current_metrics, baseline=baseline, context=context)
    emit_console_alert(alert)
    logger.info(json.dumps(alert, sort_keys=True))
    record_alert(alert)

    # Default: no email sending unless explicitly enabled via alert_cfg or env
    email_enabled = False
    email_provider = None
    email_conf: Dict[str, Any] = {}
    cooldown_seconds = 300

    if alert_cfg and isinstance(alert_cfg, dict):
        email_conf = alert_cfg.get("email", {}) or {}
        email_enabled = bool(email_conf.get("enabled", False))
        email_provider = email_conf.get("provider")
        cooldown_seconds = int(
            email_conf.get("cooldown_seconds", alert_cfg.get("cooldown_seconds", cooldown_seconds))
        )
        if os.environ.get("ALERT_SMTP_ENABLED") == "1":
            email_enabled = True
            email_provider = email_provider or "smtp"
    else:
        # Allow environment override to enable email (not recommended for default)
        email_enabled = (
            os.environ.get("ALERT_EMAIL_ENABLED") == "1"
            or os.environ.get("ALERT_SMTP_ENABLED") == "1"
        )
        if os.environ.get("ALERT_COOLDOWN_SECONDS"):
            try:
                cooldown_seconds = int(os.environ.get("ALERT_COOLDOWN_SECONDS"))
            except Exception:
                pass
        # Choose provider by environment presence of BREVO_API_KEY or SMTP settings
        if os.environ.get("ALERT_SMTP_ENABLED") == "1":
            email_provider = "smtp"
        elif os.environ.get("BREVO_API_KEY"):
            email_provider = "brevo"
        elif os.environ.get("SMTP_HOST"):
            email_provider = "smtp"

    context = context or {}
    interface = str(context.get("interface") or "unknown")
    targets = tuple(sorted(str(item) for item in (context.get("target_ips") or [])))
    incident_key = _incident_key(context)
    now = float((clock or time.time)())
    state_path = _state_file_path(alert_cfg if isinstance(alert_cfg, dict) else None)

    email_configuration_valid = True
    email_cooldown_allowed = False
    email_attempted = False
    email_result: Dict[str, Any] = {"delivered": False, "status": "not_enabled", "reason": "email_disabled"}
    should_send = False
    with _alert_state_file_lock(state_path):
        _sync_from_disk_unlocked(state_path, now=now)
        state = INCIDENT_STATE.get(incident_key)
        # Check if an ongoing incident on this interface is already active/notified
        if state is None:
            for existing_key, existing_state in INCIDENT_STATE.items():
                if existing_state.get("interface") == interface:
                    existing_targets = existing_state.get("targets", set())
                    # If current window has no specific targets, or existing has no targets,
                    # or targets overlap, link to the existing active incident
                    if not targets or not existing_targets or (set(targets) & set(existing_targets)):
                        incident_key = existing_key
                        state = existing_state
                        break

        if state is None:
            state = {
                "interface": interface,
                "notified": False,
                "normal_windows": 0,
                "targets": set(targets),
                "in_flight_until": 0.0,
                "updated_at": now,
            }
            dict.__setitem__(INCIDENT_STATE, incident_key, state)
            logger.info("INCIDENT_STARTED incident=%s", incident_key)
        state["normal_windows"] = 0
        state["updated_at"] = now
        if targets:
            state["targets"] = set(state.get("targets") or set()) | set(targets)
        in_flight_until = float(state.get("in_flight_until", 0.0) or 0.0)
        is_in_flight = (
            incident_key in EMAIL_IN_FLIGHT
            or (in_flight_until > 0.0 and 0.0 <= (in_flight_until - now) <= IN_FLIGHT_LEASE_SECONDS)
        )
        if email_enabled:
            if state.get("notified"):
                email_result = {"delivered": False, "status": "incident_active", "reason": "duplicate_incident"}
                logger.info("EMAIL_SUPPRESSED_DUPLICATE incident=%s", incident_key)
            elif is_in_flight:
                email_result = {"delivered": False, "status": "in_flight", "reason": "duplicate_in_flight"}
                logger.info("EMAIL_SUPPRESSED_IN_FLIGHT incident=%s", incident_key)
            else:
                last_sent = ALERT_LAST_SENT.get(incident_key)
                if last_sent is not None and 0 <= now - last_sent < cooldown_seconds:
                    email_result = {"delivered": False, "status": "cooldown", "reason": "cooldown"}
                else:
                    email_cooldown_allowed = True
                    EMAIL_IN_FLIGHT.add(incident_key)
                    state["in_flight_until"] = now + IN_FLIGHT_LEASE_SECONDS
                    should_send = True
        _write_state_file_unlocked(state_path, INCIDENT_STATE, ALERT_LAST_SENT)

    if should_send:
        if email_provider == "brevo":
            email_result = _send_email_via_brevo(alert, email_conf)
            email_configuration_valid = bool(email_result.get("configuration_valid", False))
            email_attempted = bool(email_result.get("attempted", False))
        elif email_provider == "smtp":
            email_result = _send_email_via_smtp(alert, email_conf)
            email_attempted = bool(email_result.get("attempted", False))
        else:
            logger.warning("No email provider configured; skipping email send")
            email_configuration_valid = False
            email_result = {"delivered": False, "status": "not_configured", "reason": "provider_missing"}
        with _alert_state_file_lock(state_path):
            _sync_from_disk_unlocked(state_path, now=now)
            EMAIL_IN_FLIGHT.discard(incident_key)
            if incident_key in INCIDENT_STATE:
                INCIDENT_STATE[incident_key]["in_flight_until"] = 0.0
                INCIDENT_STATE[incident_key]["updated_at"] = now
            if email_result.get("delivered"):
                dict.__setitem__(ALERT_LAST_SENT, incident_key, now)
                if incident_key in INCIDENT_STATE:
                    INCIDENT_STATE[incident_key]["notified"] = True
                logger.info("EMAIL_DELIVERED incident=%s", incident_key)
            _write_state_file_unlocked(state_path, INCIDENT_STATE, ALERT_LAST_SENT)
    logger.info(
        "EMAIL_ENABLED=%s EMAIL_CONFIGURATION_VALID=%s EMAIL_COOLDOWN_ALLOWED=%s "
        "EMAIL_ATTEMPTED=%s BREVO_RESPONSE_STATUS=%s EMAIL_DELIVERED/ACCEPTED=%s",
        str(email_enabled).lower(),
        str(email_configuration_valid).lower(),
        str(email_cooldown_allowed).lower(),
        str(email_attempted).lower(),
        email_result.get("status"),
        str(bool(email_result.get("delivered", False))).lower(),
    )
    return alert
