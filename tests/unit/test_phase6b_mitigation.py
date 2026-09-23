import sys
import pathlib
from datetime import datetime, timedelta, timezone
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.mitigation import MitigationManager
from ddos_detector.models import PacketRecord
from ddos_detector.aggregator import compute_window_metrics


def test_auto_block_sources_dry_run():
    # create a window with repeated source IPs
    packets = []
    for i in range(10):
        packets.append(PacketRecord(timestamp=1.0 + i, src_ip="10.0.0.1", dst_ip="127.0.0.1", packet_size=100, protocol="TCP"))
    for i in range(5):
        packets.append(PacketRecord(timestamp=20.0 + i, src_ip="10.0.0.2", dst_ip="127.0.0.1", packet_size=80, protocol="TCP"))

    wm = compute_window_metrics(packets, window_seconds=5)
    # top 2 sources expected
    from collections import Counter
    counts = Counter(p.src_ip for p in wm.raw)
    top = [ip for ip, _ in counts.most_common(2)]

    mgr = MitigationManager({"enabled": True, "dry_run": True, "mechanism": "nftables", "rule_ttl_seconds": 60})

    for src in top:
        result = mgr.apply(src, "lo", "test auto block")
        assert result["dry_run"] is True

    # ensure rules were recorded
    assert len(mgr.rules) == 2


def test_enabled_source_block_config_is_accepted():
    manager = MitigationManager(
        {
            "enabled": True,
            "dry_run": False,
            "mechanism": "nftables",
            "rule_ttl_seconds": 60,
            "auto_block_sources": True,
            "max_auto_block_sources": 5,
        }
    )
    assert manager.config.auto_block_sources is True
    assert manager.config.max_auto_block_sources == 5


def test_repeated_offender_ttl_escalates_and_is_bounded():
    manager = MitigationManager({
        "enabled": True,
        "dry_run": True,
        "mechanism": "nftables",
        "rule_ttl_seconds": 60,
        "repeated_offender": {
            "enabled": True,
            "initial_ttl_seconds": 60,
            "escalation_factor": 2,
            "max_ttl_seconds": 300,
            "history_ttl_seconds": 3600,
            "max_history_entries": 10,
        },
    })
    first = manager.apply_source("10.0.0.1", "127.0.0.1", "lo", "first")
    assert first["ttl_seconds"] == 60
    manager.rules[0].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    manager.cleanup_expired()
    second = manager.apply_source("10.0.0.1", "127.0.0.1", "lo", "second")
    assert second["ttl_seconds"] == 120
    manager.rules[0].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    manager.cleanup_expired()
    third = manager.apply_source("10.0.0.1", "127.0.0.1", "lo", "third")
    assert third["ttl_seconds"] == 240
    manager.rules[0].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    manager.cleanup_expired()
    fourth = manager.apply_source("10.0.0.1", "127.0.0.1", "lo", "fourth")
    assert fourth["ttl_seconds"] == 300


def test_duplicate_active_source_block_is_reused_in_dry_run():
    manager = MitigationManager({"enabled": True, "dry_run": True, "mechanism": "nftables"})
    first = manager.apply_source("10.0.0.2", "127.0.0.1", "lo", "first")
    second = manager.apply_source("10.0.0.2", "127.0.0.1", "lo", "repeat")
    assert first["success"] is True
    assert second["reused"] is True
    assert len(manager.rules) == 1


def test_repeated_offender_history_is_bounded_and_ip_scoped():
    manager = MitigationManager({
        "enabled": True,
        "dry_run": True,
        "mechanism": "nftables",
        "repeated_offender": {"max_history_entries": 2, "history_ttl_seconds": 3600},
    })
    for source in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        manager.apply_source(source, "127.0.0.1", "lo", "test")
        manager.rules[-1].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        manager.cleanup_expired()
    assert len(manager.offender_history) == 2
    assert ("10.0.0.3", "127.0.0.1", "lo") in manager.offender_history
