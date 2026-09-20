import sys
import pathlib
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
