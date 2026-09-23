import sys
import time
import pathlib

# ensure local src is importable
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.alerts import maybe_emit_alert, ALERT_LAST_SENT, _incident_key


class DummySMTP:
    def __init__(self, host, port, timeout=10):
        self.host = host
        self.port = port
        self.logged_in = False
        self.sent = []

    def ehlo(self):
        return True

    def login(self, user, password):
        self.logged_in = True

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

    # after cooldown, sending should work
    # simulate time advance
    key = _incident_key(None)
    ALERT_LAST_SENT[key] = time.time() - 61
    maybe_emit_alert("SUSPICIOUS", 0.82, ["a"], alert_cfg=cfg)
    assert sends['count'] == 2
