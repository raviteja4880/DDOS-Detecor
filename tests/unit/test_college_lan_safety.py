import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.alerts import build_alert, format_alert_email
from ddos_detector.baseline import BaselineEngine
from ddos_detector.detector import analyze_window
from ddos_detector.mitigation import MitigationManager
from ddos_detector.models import WindowMetric


def metric(packet_rate, byte_rate, syn_rate, connection_rate, sources, concentration=0.25):
    return WindowMetric(
        window_seconds=5,
        packets=int(packet_rate * 5),
        bytes=int(byte_rate * 5),
        packets_per_sec=packet_rate,
        bytes_per_sec=byte_rate,
        tcp_packets=int(packet_rate * 5),
        udp_packets=0,
        icmp_packets=0,
        syn_packets=int(syn_rate * 5),
        connection_attempts=int(connection_rate * 5),
        unique_src_ips=sources,
        unique_dst_ips=1,
        dst_port_distribution={80: 10},
        avg_packet_size=200,
        burst_intensity=1.0,
        dest_concentration=concentration,
        raw=None,
    )


def ready_baseline():
    baseline = BaselineEngine(history_windows=10, minimum_samples=3)
    normal = metric(100, 20000, 1, 2, 20)
    for _ in range(3):
        baseline.update(normal, is_anomalous=False)
    return baseline


def test_legitimate_mass_access_burst_is_not_immediately_high_risk():
    result = analyze_window(metric(500, 100000, 1, 2, 20), ready_baseline(), minimum_indicators=2)
    assert result.classification == "SUSPICIOUS"
    assert "SYN-rate anomaly" not in result.triggered_indicators


def test_sustained_legitimate_traffic_can_remain_observable_without_source_blocking():
    baseline = ready_baseline()
    current = metric(180, 36000, 1, 2, 20)
    first = analyze_window(current, baseline, minimum_indicators=2)
    second = analyze_window(current, baseline, minimum_indicators=2)
    assert first.classification != "HIGH_RISK"
    assert second.classification != "HIGH_RISK"


def test_single_source_flood_can_be_high_risk_without_distributed_indicator():
    result = analyze_window(metric(1200, 240000, 80, 80, 1, concentration=1.0), ready_baseline(), minimum_indicators=2)
    assert result.classification == "HIGH_RISK"
    assert "distributed-source anomaly" not in result.triggered_indicators


def test_multi_source_flood_requires_real_source_diversity():
    baseline = BaselineEngine(history_windows=10, minimum_samples=3)
    normal = metric(100, 20000, 1, 2, 1)
    for _ in range(3):
        baseline.update(normal, is_anomalous=False)
    result = analyze_window(metric(1200, 240000, 80, 80, 10, concentration=1.0), baseline, minimum_indicators=2)
    assert result.classification == "HIGH_RISK"
    assert "distributed-source anomaly" in result.triggered_indicators


def test_shared_nat_source_is_alert_only_by_default():
    manager = MitigationManager({"enabled": True, "dry_run": True})
    decision = manager.assess_source_attribution("192.168.10.25")
    assert decision["attributable"] is False
    assert decision["shared_or_nat"] is True


def test_explicitly_attributable_source_can_be_scoped_for_mitigation():
    manager = MitigationManager({
        "enabled": True,
        "dry_run": True,
        "attributable_sources": ["192.0.2.10"],
        "shared_source_networks": [],
    })
    decision = manager.assess_source_attribution("192.0.2.10")
    assert decision["attributable"] is True
    result = manager.apply_source("192.0.2.10", "192.0.2.20", "lo", "HIGH_RISK")
    assert result["success"] is True
    assert manager.rules[0].source_ip == "192.0.2.10"
    assert manager.rules[0].target == "192.0.2.20"


def test_excluded_source_never_becomes_attributable():
    manager = MitigationManager({
        "enabled": True,
        "dry_run": True,
        "attributable_sources": ["192.0.2.10"],
        "excluded_sources": ["192.0.2.10"],
        "shared_source_networks": [],
    })
    decision = manager.assess_source_attribution("192.0.2.10")
    assert decision["attributable"] is False
    assert "trusted" in decision["reason"]


def test_source_target_identity_is_rejected():
    manager = MitigationManager({"enabled": True, "dry_run": True})
    result = manager.apply_source("127.0.0.1", "127.0.0.1", "lo", "HIGH_RISK")
    assert result["error"] == "source_target_conflict"


def test_alert_distinguishes_suppressed_shared_nat_mitigation():
    alert = build_alert(
        "HIGH_RISK",
        0.9,
        ["SYN-rate anomaly"],
        current_metrics={"packets_per_sec": 1200, "unique_src_ips": 20},
        context={
            "interface": "lo",
            "source_ips": ["192.168.10.25"],
            "target_ips": ["192.0.2.20"],
            "mitigation": {
                "decision": "Detected but not automatically blocked",
                "reason": "Source IP is in a configured shared/NAT network.",
                "shared_nat_ambiguous": True,
            },
        },
    )
    body = format_alert_email(alert)
    assert "Detected but not automatically blocked" in body
    assert "Shared/NAT ambiguity: YES" in body
