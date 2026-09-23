import pathlib
import sys
from datetime import timedelta

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.mitigation import MitigationManager


POLICY = {
    "enabled": True,
    "dry_run": True,
    "auto_block_sources": True,
    "max_auto_block_sources": 3,
    "repeated_offender": {
        "enabled": True,
        "initial_ttl_seconds": 60,
        "escalation_factor": 2,
        "max_ttl_seconds": 300,
        "history_ttl_seconds": 3600,
        "max_history_entries": 2,
    },
}


def _manager(**overrides):
    config = {**POLICY, **overrides}
    return MitigationManager(config)


def _offense(manager, source="10.0.0.1"):
    return manager.apply_source(source, "127.0.0.1", "lo", "HIGH_RISK source")


def _expire(manager, source="10.0.0.1"):
    manager.rules[0].expires_at -= timedelta(seconds=301)
    manager.cleanup_expired()


def test_escalates_first_second_third_and_caps_duration():
    manager = _manager()
    first = _offense(manager)
    assert first["success"] is True
    assert 59 <= (manager.rules[0].expires_at - manager.rules[0].created_at).total_seconds() <= 61

    _expire(manager)
    second = _offense(manager)
    assert second["success"] is True
    assert 119 <= (manager.rules[0].expires_at - manager.rules[0].created_at).total_seconds() <= 121

    _expire(manager)
    third = _offense(manager)
    assert third["success"] is True
    assert 239 <= (manager.rules[0].expires_at - manager.rules[0].created_at).total_seconds() <= 241

    _expire(manager)
    fourth = _offense(manager)
    assert fourth["success"] is True
    assert 299 <= (manager.rules[0].expires_at - manager.rules[0].created_at).total_seconds() <= 301


def test_duplicate_active_offense_does_not_create_rule():
    manager = _manager()
    assert _offense(manager)["success"] is True
    duplicate = _offense(manager)
    assert duplicate["success"] is False
    assert duplicate["error"] == "already_blocked"
    assert len(manager.rules) == 1


def test_expiration_allows_new_block_and_preserves_history():
    manager = _manager()
    _offense(manager)
    _expire(manager)
    result = _offense(manager)
    assert result["success"] is True
    assert manager.offender_history[("10.0.0.1", "127.0.0.1", "lo")]["block_count"] == 2


def test_source_limit_and_independent_sources():
    manager = _manager(max_auto_block_sources=2)
    assert _offense(manager, "10.0.0.1")["success"]
    assert _offense(manager, "10.0.0.2")["success"]
    limited = _offense(manager, "10.0.0.3")
    assert limited["success"] is False
    assert limited["error"] == "source_limit_reached"
    assert len(manager.rules) == 2


def test_bounded_history_and_restart_reset():
    manager = _manager()
    for source in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        _offense(manager, source)
        manager.rules[-1].expires_at -= timedelta(seconds=301)
        manager.cleanup_expired()
    assert len(manager.offender_history) <= 2

    restarted = _manager()
    result = _offense(restarted)
    assert result["success"] is True
    assert restarted.offender_history[("10.0.0.1", "127.0.0.1", "lo")]["block_count"] == 1


def test_disabled_and_dry_run_never_call_firewall():
    manager = _manager(enabled=False)
    result = _offense(manager)
    assert result["error"] == "mitigation_disabled"

    manager = _manager(dry_run=True)
    result = _offense(manager)
    assert result["dry_run"] is True


def test_invalid_and_excluded_sources_are_rejected():
    manager = _manager(excluded_sources=["10.0.0.9"])
    invalid = manager.apply_source("not-an-ip", "127.0.0.1", "lo", "HIGH_RISK")
    assert invalid["error"] == "invalid_source"

    excluded = manager.apply_source("10.0.0.9", "127.0.0.1", "lo", "HIGH_RISK")
    assert excluded["error"] == "source_excluded"


def test_failed_rule_creation_is_reported_as_failed_and_logged(monkeypatch):
    manager = _manager(dry_run=False, enabled=True)
    monkeypatch.setattr("ddos_detector.mitigation.os.name", "posix", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.platform.system", lambda: "Linux", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: tool == "nft")
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._interface_exists", lambda self, interface: interface == "lo", raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.os.geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._nft_rule_handles", lambda self, rule_id: [])
    manager._ensure_nftables_rule = lambda rule: (_ for _ in ()).throw(RuntimeError("boom"))
    result = manager.apply_source("10.0.0.5", "127.0.0.1", "lo", "HIGH_RISK")
    assert result["success"] is False
    assert result["error"] == "mitigation_failed"
    assert any(entry["status"] == "failed" for entry in manager.audit_log)


def test_audit_log_reads_structured_metadata():
    manager = _manager(dry_run=True)
    result = manager.apply_source("10.0.0.7", "127.0.0.1", "lo", "HIGH_RISK", classification="HIGH_RISK", score=0.91)
    assert result["success"] is True
    assert manager.audit_log[-1]["event"] == "mitigation_applied"
    assert manager.audit_log[-1]["classification"] == "HIGH_RISK"
    assert manager.audit_log[-1]["source"] == "10.0.0.7"
