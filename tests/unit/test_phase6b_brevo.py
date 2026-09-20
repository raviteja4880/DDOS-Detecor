import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import requests

from ddos_detector.alerts import maybe_emit_alert, ALERT_LAST_SENT


def test_brevo_send_and_cooldown(monkeypatch):
    # ensure no prior state
    ALERT_LAST_SENT.clear()

    # enable email via alert_cfg
    cfg = {"email": {"enabled": True, "provider": "brevo", "to": "ops@example.local"}, "cooldown_seconds": 0}

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

    alert = maybe_emit_alert('HIGH_RISK', 0.99, ['test'], current_metrics={'packets_per_sec': 1000}, baseline={'packets_per_sec': 100}, alert_cfg=cfg)
    assert alert is not None
    assert posted['count'] == 1

    # cooldown should prevent immediate resend
    maybe_emit_alert('HIGH_RISK', 0.99, ['test'], alert_cfg={'email': {'enabled': True, 'provider': 'brevo', 'to': 'ops@example.local'}, 'cooldown_seconds': 60})
    assert posted['count'] == 1

    # simulate expiry
    key = 'HIGH_RISK|test'
    ALERT_LAST_SENT[key] = ALERT_LAST_SENT.get(key, 0) - 61
    maybe_emit_alert('HIGH_RISK', 0.99, ['test'], alert_cfg={'email': {'enabled': True, 'provider': 'brevo', 'to': 'ops@example.local'}, 'cooldown_seconds': 60})
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
