import sys
import pathlib
import pytest
import logging
import threading

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import requests

from ddos_detector.alerts import maybe_emit_alert, ALERT_LAST_SENT, INCIDENT_STATE, mark_normal_window


@pytest.fixture(autouse=True)
def clear_incident_state():
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    yield
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()


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

    # Cooldown expiry does not re-notify an already active incident.
    current_time[0] = 161.0
    maybe_emit_alert('HIGH_RISK', 0.99, ['test'], alert_cfg=cfg, clock=lambda: current_time[0])
    assert posted['count'] == 1


def test_twenty_windows_same_incident_send_one_email(monkeypatch):
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    posted = {"count": 0}

    def fake_post(url, json=None, headers=None, timeout=10):
        posted["count"] += 1
        class Response:
            status_code = 201
            text = "created"
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    context = {"interface": "lo", "target_ips": ["127.0.0.1"], "target_ports": [18080]}

    for window in range(20):
        maybe_emit_alert(
            "HIGH_RISK" if window % 3 else "SUSPICIOUS",
            0.4 + window / 100,
            [f"indicator-{window}"],
            context={**context, "source_ips": [f"10.0.0.{window + 1}"]},
            alert_cfg=cfg,
            clock=lambda window=window: window * 61,
        )

    assert posted["count"] == 1


def test_one_hundred_windows_same_incident_send_one_email(monkeypatch):
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    posted = {"count": 0}

    def fake_post(url, json=None, headers=None, timeout=10):
        posted["count"] += 1
        class Response:
            status_code = 201
            text = "created"
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    cfg = {"email": {"enabled": True, "provider": "brevo", "cooldown_seconds": 1}}
    context = {"interface": "lo", "target_ips": ["127.0.0.1"], "target_ports": [18080]}

    for window in range(100):
        maybe_emit_alert(
            "HIGH_RISK",
            0.5 + (window % 50) / 100,
            [f"indicator-{window % 4}"],
            context={**context, "source_ips": [f"10.0.0.{window + 1}"]},
            alert_cfg=cfg,
            clock=lambda window=window: window * 2,
        )

    assert posted["count"] == 1


def test_notified_incident_is_not_rearmed_by_timestamp_store_loss(monkeypatch):
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    posted = {"count": 0}

    def fake_post(url, json=None, headers=None, timeout=10):
        posted["count"] += 1
        class Response:
            status_code = 201
            text = "created"
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 0}
    context = {"interface": "lo", "target_ips": ["127.0.0.1"], "target_ports": [18080]}

    maybe_emit_alert("HIGH_RISK", 1.0, ["first"], context=context, alert_cfg=cfg)
    ALERT_LAST_SENT.clear()
    maybe_emit_alert("HIGH_RISK", 0.9, ["second"], context=context, alert_cfg=cfg)

    assert posted["count"] == 1
    assert INCIDENT_STATE[next(iter(INCIDENT_STATE))]["notified"] is True


def test_incident_rearms_after_two_normal_windows(monkeypatch):
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    posted = {"count": 0}

    def fake_post(url, json=None, headers=None, timeout=10):
        posted["count"] += 1
        class Response:
            status_code = 201
            text = "created"
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    context = {"interface": "lo", "target_ips": ["127.0.0.1"], "target_ports": [18080]}

    maybe_emit_alert("HIGH_RISK", 0.9, ["attack"], context=context, alert_cfg=cfg, clock=lambda: 0)
    mark_normal_window("lo", required_windows=2)
    mark_normal_window("lo", required_windows=2)
    maybe_emit_alert("HIGH_RISK", 0.9, ["new attack"], context=context, alert_cfg=cfg, clock=lambda: 1)

    assert posted["count"] == 2


def test_concurrent_same_incident_notification_is_single_send(monkeypatch):
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    calls = {"count": 0}
    entered = threading.Event()
    release = threading.Event()

    def fake_post(url, json=None, headers=None, timeout=10):
        calls["count"] += 1
        entered.set()
        release.wait(timeout=2)
        class Response:
            status_code = 201
            text = "created"
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    context = {"interface": "lo", "target_ips": ["127.0.0.1"], "target_ports": [18080]}
    threads = [
        threading.Thread(
            target=maybe_emit_alert,
            kwargs={"classification": "HIGH_RISK", "score": 0.9, "reasons": ["attack"], "context": context, "alert_cfg": cfg},
        )
        for _ in range(2)
    ]
    threads[0].start()
    assert entered.wait(timeout=2)
    threads[1].start()
    threads[1].join(timeout=2)
    release.set()
    threads[0].join(timeout=2)

    assert calls["count"] == 1


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
    assert "BREVO_RESPONSE_STATUS=incident_active" in caplog.text


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
    assert calls["count"] == 1


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


def test_varying_ephemeral_ports_send_only_one_email_until_recovery(monkeypatch):
    """Live traffic continuously opens new ephemeral client ports. These changing ports
    must not trigger new incident emails on every window. Exactly one alert should be sent
    until the incident is resolved."""
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()
    posted = {"count": 0}

    def fake_post(url, json=None, headers=None, timeout=10):
        posted["count"] += 1
        class Response:
            status_code = 201
            text = "created"
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setenv("BREVO_API_KEY", "DUMMY")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.local")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "ops@example.local")
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}

    # Simulate 15 windows with changing ephemeral ports and changing/idle target IPs
    for i in range(15):
        context = {
            "interface": "lo",
            "target_ips": ["127.0.0.1"] if i < 10 else [],
            "target_ports": [18080, 50000 + i],
            "source_ips": ["127.0.0.1"],
        }
        maybe_emit_alert(
            "HIGH_RISK" if i == 0 else "SUSPICIOUS",
            0.9 if i == 0 else 0.62,
            ["packet-rate anomaly"] if i == 0 else ["destination concentration anomaly"],
            context=context,
            alert_cfg=cfg,
            clock=lambda i=i: float(i),
        )

    # Exactly ONE alert must have been sent across all 15 windows
    assert posted["count"] == 1

    # Now abnormal activity resolves (2 normal windows)
    mark_normal_window("lo", required_windows=2)
    mark_normal_window("lo", required_windows=2)

    # A subsequent abnormal activity occurs later
    context_new = {
        "interface": "lo",
        "target_ips": ["127.0.0.1"],
        "target_ports": [18080, 60001],
    }
    maybe_emit_alert("HIGH_RISK", 0.95, ["packet-rate anomaly"], context=context_new, alert_cfg=cfg, clock=lambda: 100.0)

    # Exactly ONE new alert is sent for the new incident
    assert posted["count"] == 2


def test_missing_brevo_configuration_is_safe_and_retryable(monkeypatch, caplog):
    for name in (
        "BREVO_API_KEY",
        "BREVO_SENDER_EMAIL",
        "BREVO_SENDER_NAME",
        "BREVO_ALERT_RECIPIENT",
    ):
        monkeypatch.delenv(name, raising=False)

    calls = []

    def fake_post(url, json=None, headers=None, timeout=10):
        calls.append(url)

        class Response:
            status_code = 201
            text = "created"

        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    config = {"email": {"enabled": True, "provider": "brevo"}}
    context = {"interface": "eth-test", "target_ips": ["192.0.2.10"]}

    maybe_emit_alert("HIGH_RISK", 0.9, ["synthetic test"], context=context, alert_cfg=config)

    assert calls == []
    assert "reason=missing_configuration" in caplog.text
    assert "BREVO_API_KEY" in caplog.text
    assert "EMAIL_ATTEMPTED=false" in caplog.text

    monkeypatch.setenv("BREVO_API_KEY", "test-only-placeholder")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.test")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "recipient@example.test")
    maybe_emit_alert("HIGH_RISK", 0.9, ["synthetic test"], context=context, alert_cfg=config)

    assert len(calls) == 1
    assert "test-only-placeholder" not in caplog.text


def test_cross_restart_suppresses_duplicate_until_recovered_and_never_stores_secrets(
    monkeypatch, tmp_path
):
    from ddos_detector.alerts import reset_memory_state_for_restart

    state_file = tmp_path / "alert_state.json"
    monkeypatch.setenv("DDOS_DETECTOR_ALERT_STATE_FILE", str(state_file))
    ALERT_LAST_SENT.clear()
    INCIDENT_STATE.clear()

    secret_key = "xkeysib-do-not-persist-me-999"
    monkeypatch.setenv("BREVO_API_KEY", secret_key)
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.test")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "recipient@example.test")

    calls = []

    class Accepted:
        status_code = 201
        text = "created"

    monkeypatch.setattr(requests, "post", lambda url, **kw: calls.append(url) or Accepted())

    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    context = {"interface": "lo", "target_ips": ["127.0.0.1"], "target_ports": [8080]}

    # Process 1 sends initial notification
    maybe_emit_alert("HIGH_RISK", 0.92, ["SYN-rate anomaly"], context=context, alert_cfg=cfg, clock=lambda: 1000.0)
    assert len(calls) == 1
    assert state_file.is_file()
    persisted_raw = state_file.read_text(encoding="utf-8")
    assert secret_key not in persisted_raw
    assert "sender@example.test" not in persisted_raw
    assert "recipient@example.test" not in persisted_raw
    assert "SYN-rate anomaly" not in persisted_raw

    # Simulate monitor process restart: wipe in-memory dictionaries only
    reset_memory_state_for_restart()
    assert not INCIDENT_STATE
    assert not ALERT_LAST_SENT

    # Process 2 sees the same active incident after restart -> suppressed!
    maybe_emit_alert("HIGH_RISK", 0.95, ["SYN-rate anomaly"], context=context, alert_cfg=cfg, clock=lambda: 1080.0)
    assert len(calls) == 1

    # One normal window before another restart is also preserved across restart
    mark_normal_window("lo", required_windows=2)
    reset_memory_state_for_restart()
    mark_normal_window("lo", required_windows=2)

    # After 2 consecutive normal windows across restart, incident is re-armed
    maybe_emit_alert("HIGH_RISK", 0.96, ["SYN-rate anomaly"], context=context, alert_cfg=cfg, clock=lambda: 1200.0)
    assert len(calls) == 2


def test_corrupt_state_file_fails_safely_and_does_not_block_alert(monkeypatch, tmp_path, caplog):
    state_file = tmp_path / "corrupt_state.json"
    state_file.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("DDOS_DETECTOR_ALERT_STATE_FILE", str(state_file))
    monkeypatch.setenv("BREVO_API_KEY", "test-only-placeholder")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.test")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "recipient@example.test")

    calls = []

    class Accepted:
        status_code = 201
        text = "created"

    monkeypatch.setattr(requests, "post", lambda url, **kw: calls.append(url) or Accepted())
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}
    context = {"interface": "lo", "target_ips": ["127.0.0.1"]}

    alert = maybe_emit_alert("HIGH_RISK", 0.91, ["packet-rate anomaly"], context=context, alert_cfg=cfg, clock=lambda: 500.0)
    assert alert is not None
    assert len(calls) == 1
    assert "Corrupt or unreadable alert state file" in caplog.text


def test_crashed_in_flight_lease_expires_and_does_not_suppress_forever(monkeypatch, tmp_path):
    import json as _json
    from ddos_detector.alerts import IN_FLIGHT_LEASE_SECONDS, _incident_key, reset_memory_state_for_restart

    state_file = tmp_path / "lease_state.json"
    monkeypatch.setenv("DDOS_DETECTOR_ALERT_STATE_FILE", str(state_file))
    monkeypatch.setenv("BREVO_API_KEY", "test-only-placeholder")
    monkeypatch.setenv("BREVO_SENDER_EMAIL", "sender@example.test")
    monkeypatch.setenv("BREVO_ALERT_RECIPIENT", "recipient@example.test")

    context = {"interface": "lo", "target_ips": ["127.0.0.1"]}
    key = _incident_key(context)
    # Simulate a process that crashed while an email was in flight at t=100.0
    state_file.write_text(
        _json.dumps({
            "version": 1,
            "incidents": {
                key: {
                    "interface": "lo",
                    "notified": False,
                    "normal_windows": 0,
                    "targets": ["127.0.0.1"],
                    "in_flight_until": 100.0 + IN_FLIGHT_LEASE_SECONDS,
                    "updated_at": 100.0,
                }
            },
            "last_sent": {},
        }),
        encoding="utf-8",
    )
    reset_memory_state_for_restart()

    calls = []

    class Accepted:
        status_code = 201
        text = "created"

    monkeypatch.setattr(requests, "post", lambda url, **kw: calls.append(url) or Accepted())
    cfg = {"email": {"enabled": True, "provider": "brevo"}, "cooldown_seconds": 60}

    # During active lease (t=110.0), duplicate send from another process is suppressed
    maybe_emit_alert("HIGH_RISK", 0.9, ["test"], context=context, alert_cfg=cfg, clock=lambda: 110.0)
    assert len(calls) == 0

    # After lease expires (t=135.0), crashed un-notified incident retries and succeeds
    maybe_emit_alert("HIGH_RISK", 0.9, ["test"], context=context, alert_cfg=cfg, clock=lambda: 135.0)
    assert len(calls) == 1

