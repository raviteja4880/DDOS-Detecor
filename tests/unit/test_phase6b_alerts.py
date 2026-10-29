import sys
import time
import pathlib
import pytest

# ensure local src is importable
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.alerts import maybe_emit_alert, ALERT_LAST_SENT, _incident_key
from ddos_detector.alerts import INCIDENT_STATE, EMAIL_IN_FLIGHT


@pytest.fixture(autouse=True)
def clear_incident_state():
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    EMAIL_IN_FLIGHT.clear()
    yield
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    EMAIL_IN_FLIGHT.clear()


class DummySMTP:
    def __init__(self, host, port, timeout=10):
        self.host = host
        self.port = port
        self.logged_in = False
        self.tls_started = False
        self.sent = []

    def ehlo(self):
        return True

    def login(self, user, password):
        self.logged_in = True

    def starttls(self):
        self.tls_started = True

    def send_message(self, msg):
        self.sent.append(msg)

    def quit(self):
        return True


def test_maybe_emit_alert_sends_email(monkeypatch):
    # set env vars to enable SMTP
    monkeypatch.setenv("ALERT_SMTP_ENABLED", "1")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.local")
    monkeypatch.setenv("SMTP_PORT", "25")
    monkeypatch.setenv("SMTP_FROM", "alert@example.local")
    monkeypatch.setenv("SMTP_TO", "ops@example.local")

    sent = {"count": 0}

    def fake_smtp(host, port, timeout=10):
        sent['count'] += 1
        return DummySMTP(host, port)

    monkeypatch.setattr("smtplib.SMTP", fake_smtp)

    # ensure no previous cooldown interference
    ALERT_LAST_SENT.clear()

    alert = maybe_emit_alert(
        "HIGH_RISK",
        0.99,
        ["test spike"],
        current_metrics={"packets_per_sec": 1000},
        baseline={"packets_per_sec": 100},
        alert_cfg={"cooldown_seconds": 0},
    )
    assert alert is not None
    # ensure SMTP send attempted
    assert sent['count'] == 1


def test_smtp_uses_starttls_before_authentication(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.local")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "user")
    monkeypatch.setenv("SMTP_PASSWORD", "password")
    monkeypatch.setenv("SMTP_FROM", "alert@example.local")
    monkeypatch.setenv("SMTP_TO", "ops@example.local")

    smtp_instances = []

    def fake_smtp(host, port, timeout=10):
        smtp = DummySMTP(host, port)
        smtp_instances.append(smtp)
        return smtp

    monkeypatch.setattr("smtplib.SMTP", fake_smtp)

    from ddos_detector.alerts import _send_email_via_smtp

    result = _send_email_via_smtp(
        {"classification": "HIGH_RISK", "score": 0.9},
        {},
    )

    assert result["delivered"] is True
    assert smtp_instances[0].tls_started is True
    assert smtp_instances[0].logged_in is True


def test_smtp_failure_to_negotiate_starttls_does_not_send(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.local")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "user")
    monkeypatch.setenv("SMTP_PASSWORD", "password")
    monkeypatch.setenv("SMTP_FROM", "alert@example.local")
    monkeypatch.setenv("SMTP_TO", "ops@example.local")

    class InsecureSMTP(DummySMTP):
        def starttls(self):
            raise RuntimeError("STARTTLS unavailable")

    smtp = InsecureSMTP("smtp.example.local", 587)
    monkeypatch.setattr("smtplib.SMTP", lambda host, port, timeout=10: smtp)

    from ddos_detector.alerts import _send_email_via_smtp

    result = _send_email_via_smtp(
        {"classification": "HIGH_RISK", "score": 0.9},
        {},
    )

    assert result["delivered"] is False
    assert smtp.logged_in is False
    assert smtp.sent == []


def test_maybe_emit_alert_respects_cooldown(monkeypatch):
    monkeypatch.setenv("ALERT_SMTP_ENABLED", "1")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.local")
    monkeypatch.setenv("SMTP_PORT", "25")
    monkeypatch.setenv("SMTP_FROM", "alert@example.local")
    monkeypatch.setenv("SMTP_TO", "ops@example.local")

    sends = {"count": 0}

    def fake_smtp(host, port, timeout=10):
        sends['count'] += 1
        return DummySMTP(host, port)

    monkeypatch.setattr("smtplib.SMTP", fake_smtp)

    ALERT_LAST_SENT.clear()

    cfg = {"cooldown_seconds": 60}

    # first send
    maybe_emit_alert("SUSPICIOUS", 0.8, ["a"], alert_cfg=cfg)
    # immediate second send should be skipped
    maybe_emit_alert("SUSPICIOUS", 0.81, ["a"], alert_cfg=cfg)
    assert sends['count'] == 1

    # Cooldown expiry does not re-notify an already active incident.
    # simulate time advance
    key = _incident_key(None)
    ALERT_LAST_SENT[key] = time.time() - 61
    maybe_emit_alert("SUSPICIOUS", 0.82, ["a"], alert_cfg=cfg)
    assert sends['count'] == 1
