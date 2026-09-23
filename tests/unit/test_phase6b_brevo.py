import sys
import pathlib
import pytest
import logging

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import requests

from ddos_detector.alerts import maybe_emit_alert, ALERT_LAST_SENT


def test_brevo_send_and_cooldown(monkeypatch):
    # ensure no prior state
    ALERT_LAST_SENT.clear()

    # enable email via alert_cfg
    cfg = {"email": {"enabled": True, "provider": "brevo", "to": "ops@example.local"}, "cooldown_seconds": 60}
    current_time = [100.0]

    posted = {"count": 0, "last": None}

    def fake_post(url, json=None, headers=None, timeout=10):
        posted['count'] += 1
        posted['last'] = {'url': url, 'json': json, 'headers': headers}
        class R:
            status_code = 201
            text = 'created'
        return R()

    import requests as _requests
    monkeypatch.setattr(_requests, 'post', fake_post)
    # no direct attribute on ddos_detector.alerts; the alerts module does local import of requests

    # ensure env API key not required because config provides nothing; but we can set env
    monkeypatch.setenv('BREVO_API_KEY', 'DUMMY')
    monkeypatch.setenv('BREVO_SENDER_EMAIL', 'sender@example.local')
    monkeypatch.setenv('BREVO_ALERT_RECIPIENT', 'ops@example.local')

    alert = maybe_emit_alert('HIGH_RISK', 0.99, ['test'], current_metrics={'packets_per_sec': 1000}, baseline={'packets_per_sec': 100}, alert_cfg=cfg, clock=lambda: current_time[0])
    assert alert is not None
    assert posted['count'] == 1

    # cooldown should prevent immediate resend
    maybe_emit_alert('HIGH_RISK', 0.99, ['test'], alert_cfg=cfg, clock=lambda: current_time[0])
    assert posted['count'] == 1

    # simulate expiry
    current_time[0] = 161.0
    maybe_emit_alert('HIGH_RISK', 0.99, ['test'], alert_cfg=cfg, clock=lambda: current_time[0])
    assert posted['count'] == 2


def test_brevo_payload_contains_contextual_incident_details(monkeypatch):
    ALERT_LAST_SENT.clear()
    cfg = {"email": {"enabled": True, "provider": "brevo", "to": "ops@example.local"}, "cooldown_seconds": 0}
    posted = {}

    def fake_post(url, json=None, headers=None, timeout=10):
        posted["payload"] = json
        class Response:
            status_code = 201
            text = "created"
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")

    maybe_emit_alert(
        "HIGH_RISK",
        0.97,
        ["packet-rate anomaly", "SYN-rate anomaly"],
        current_metrics={
            "packets_per_sec": 236,
            "bytes_per_sec": 43930,
            "syn_rate": 47,
            "connection_rate": 47,
            "unique_src_ips": 3,
            "dest_concentration": 1.0,
        },
        baseline={"packets_per_sec": 4.96, "bytes_per_sec": 788, "syn_rate": 4, "connection_rate": 4},
        context={
            "interface": "eth0",
            "source_ips": ["192.168.1.25", "192.168.1.26", "192.168.1.27"],
            "target_ips": ["192.168.1.10"],
            "target_ports": [80],
            "mitigation": {
                "enabled": True,
                "auto_block_sources": True,
                "mechanism": "nftables",
                "max_auto_block_sources": 5,
                "rule_ttl_seconds": 60,
            },
        },
        alert_cfg=cfg,
    )

    body = posted["payload"]["textContent"]
    html = posted["payload"]["htmlContent"]
    assert "WHAT DID THE SYSTEM DO?" in body
    assert "current 236 packets/sec vs baseline 4.96 packets/sec" in body
    assert "192.168.1.25" in body
    assert "192.168.1.10" in body
    assert "Maximum sources blocked: 5" in body
    assert "Rule lifetime: 60 seconds" in body
    assert "<html>" in html
    assert "HIGH RISK TRAFFIC DETECTED" in html
    assert "Packet rate" in html
    assert "192.168.1.25" in html
    assert "nftables" in html


@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
def test_brevo_http_errors_do_not_raise(monkeypatch, status_code, caplog):
    ALERT_LAST_SENT.clear()
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_SENDER_NAME", "Alert")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")

    class Response:
        def __init__(self):
            self.status_code = status_code

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: Response())
    alert = maybe_emit_alert(
        "HIGH_RISK",
        0.9,
        ["test"],
        alert_cfg={"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 0},
    )
    assert alert is not None
    assert f"BREVO_RESPONSE_STATUS={status_code}" in caplog.text
    assert "EMAIL_DELIVERED=false" in caplog.text


def test_brevo_timeout_does_not_raise(monkeypatch, caplog):
    ALERT_LAST_SENT.clear()
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")

    def fail(*args, **kwargs):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(requests, "post", fail)
    maybe_emit_alert(
        "HIGH_RISK",
        0.9,
        ["test"],
        alert_cfg={"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 0},
    )
    assert "monitoring continues" in caplog.text


def test_brevo_diagnostics_show_first_attempt_and_cooldown(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    ALERT_LAST_SENT.clear()
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    calls = {"count": 0}

    class Response:
        status_code = 201

    def fake_post(*args, **kwargs):
        calls["count"] += 1
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    maybe_emit_alert("HIGH_RISK", 0.9, ["diagnostic"], alert_cfg=cfg)
    maybe_emit_alert("HIGH_RISK", 0.9, ["diagnostic"], alert_cfg=cfg)
    assert calls["count"] == 1
    assert "EMAIL_COOLDOWN_ALLOWED=true" in caplog.text
    assert "EMAIL_ATTEMPTED=true" in caplog.text
    assert "BREVO_RESPONSE_STATUS=201" in caplog.text
    assert "EMAIL_DELIVERED/ACCEPTED=true" in caplog.text
    assert "BREVO_RESPONSE_STATUS=cooldown" in caplog.text


def test_global_cooldown_spans_classification_score_and_indicators(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    ALERT_LAST_SENT.clear()
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    calls = {"count": 0}

    class Response:
        status_code = 201

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: (calls.__setitem__("count", calls["count"] + 1) or Response()))
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    context = {"interface": "lo", "target_ips": ["127.0.0.2"], "target_ports": [80], "source_ips": ["127.0.0.1"]}
    current_time = [100.0]
    maybe_emit_alert("HIGH_RISK", 0.92, ["packet-rate anomaly"], context=context, alert_cfg=cfg, clock=lambda: current_time[0])
    maybe_emit_alert("HIGH_RISK", 0.83, ["byte-rate anomaly", "SYN-rate anomaly"], context={**context, "source_ips": ["127.0.0.3"]}, alert_cfg=cfg, clock=lambda: current_time[0])
    maybe_emit_alert("SUSPICIOUS", 0.33, ["connection-rate anomaly"], context=context, alert_cfg=cfg, clock=lambda: current_time[0])
    assert calls["count"] == 1
    assert caplog.text.count('"classification": "HIGH_RISK"') == 2
    assert caplog.text.count('"classification": "SUSPICIOUS"') == 1

    current_time[0] = 160.0
    maybe_emit_alert("HIGH_RISK", 0.91, ["new indicator"], context=context, alert_cfg=cfg, clock=lambda: current_time[0])
    assert calls["count"] == 2


def test_separate_incident_has_independent_cooldown(monkeypatch):
    ALERT_LAST_SENT.clear()
    import ddos_detector.alerts as alerts
    calls = {"count": 0}
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")

    class Response:
        status_code = 201

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: (calls.__setitem__("count", calls["count"] + 1) or Response()))
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    clock = lambda: 100.0
    maybe_emit_alert("HIGH_RISK", 0.9, ["incident-a"], context={"interface": "lo", "target_ips": ["127.0.0.2"]}, alert_cfg=cfg, clock=clock)
    maybe_emit_alert("HIGH_RISK", 0.9, ["incident-b"], context={"interface": "lo", "target_ips": ["127.0.0.3"]}, alert_cfg=cfg, clock=clock)
    assert calls["count"] == 2
    assert len(alerts.ALERT_LAST_SENT) == 2


def test_delivery_failure_does_not_consume_cooldown(monkeypatch):
    ALERT_LAST_SENT.clear()
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    calls = {"count": 0}

    def fail_then_succeed(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise requests.Timeout("timeout")
        class Response:
            status_code = 201
        return Response()

    monkeypatch.setattr(requests, "post", fail_then_succeed)
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    context = {"interface": "lo", "target_ips": ["127.0.0.2"]}
    maybe_emit_alert("HIGH_RISK", 0.9, ["failure"], context=context, alert_cfg=cfg, clock=lambda: 100.0)
    maybe_emit_alert("HIGH_RISK", 0.9, ["retry"], context=context, alert_cfg=cfg, clock=lambda: 101.0)
    assert calls["count"] == 2
    assert len(ALERT_LAST_SENT) == 1


def test_brevo_network_and_malformed_responses_are_non_fatal(monkeypatch, caplog):
    ALERT_LAST_SENT.clear()
    secret = "super-secret-key"
    monkeypatch.setenv("BREVO_API_KEY", secret)
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: (_ for _ in ()).throw(
        requests.ConnectionError(secret)
    ))
    maybe_emit_alert(
        "HIGH_RISK", 0.9, ["test"],
        alert_cfg={"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 0},
    )
    assert secret not in caplog.text

    class MalformedResponse:
        pass

    ALERT_LAST_SENT.clear()
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: MalformedResponse())
    maybe_emit_alert(
        "HIGH_RISK", 0.9, ["test"],
        alert_cfg={"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 0},
    )
    assert "monitoring continues" in caplog.text
