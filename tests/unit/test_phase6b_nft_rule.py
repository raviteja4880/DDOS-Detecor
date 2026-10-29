import sys
import pathlib
import json
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.mitigation import MitigationManager, MitigationRule


def test_nft_rule_uses_saddr(monkeypatch):
    mgr = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables", "rule_ttl_seconds": 60})

    # force linux/tool checks to pass
    monkeypatch.setattr(mgr, '_tool_available', lambda tool: True)
    monkeypatch.setattr(mgr, '_is_linux', lambda: True)

    captured = {"add_rule_args": None}

    def fake_subprocess_run(cmd, shell=False, capture_output=False, text=False, check=False, timeout=None):
        # cmd is a list; detect 'add rule' invocation
        if isinstance(cmd, list) and len(cmd) >= 5 and cmd[1] == 'add' and cmd[2] == 'rule':
            captured['add_rule_args'] = cmd
            class R:
                returncode = 0
                stdout = ''
                stderr = ''
            return R()
        # For nft -j list chain ... return a JSON with a rule including our comment
        if isinstance(cmd, list) and cmd[:3] == ['nft', '-j', 'list']:
            payload = {'nftables': [{'rule': {'table': mgr.TABLE_NAME, 'chain': mgr.CHAIN_NAME, 'comment': 'ddos_detector:source-live-1', 'handle': '42'}}]}
            class R:
                returncode = 0
                stdout = json.dumps(payload)
                stderr = ''
            return R()
        # other commands (add table/chain) return success
        class R:
            returncode = 0
            stdout = ''
            stderr = ''
        return R()

    monkeypatch.setattr('subprocess.run', fake_subprocess_run)

    # construct a live MitigationRule with source match
    rule = MitigationRule(rule_id='source-live-1', rule_type='nftables', target='10.0.0.1', interface='lo', reason='test', match='saddr', source_ip='10.0.0.2')

    handle = mgr._ensure_nftables_rule(rule)
    assert captured['add_rule_args'] is not None
    args = [str(x) for x in captured['add_rule_args']]
    assert args[6:14] == ["ip", "saddr", "10.0.0.2", "ip", "daddr", "10.0.0.1", "iifname", "lo"]
    assert args[14:16] == ["drop", "comment"]
    assert args[16] == '"ddos_detector:source-live-1"'
    assert handle == '42'


def test_rule_ids_are_unique_and_encode_expiration():
    manager = MitigationManager({"enabled": True, "dry_run": True, "mechanism": "nftables", "rule_ttl_seconds": 60})
    first = manager._new_rule_id(True, datetime.now(timezone.utc) + timedelta(seconds=60))
    second = manager._new_rule_id(True, datetime.now(timezone.utc) + timedelta(seconds=60))
    assert first != second
    assert manager._rule_id_expired(first, datetime.now(timezone.utc) + timedelta(seconds=61))


def test_duplicate_live_source_rule_is_reused(monkeypatch):
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    monkeypatch.setattr(manager, "_is_linux", lambda: True)
    monkeypatch.setattr(manager, "_tool_available", lambda tool: True)
    monkeypatch.setattr(manager, "_discover_nft_application_rules", lambda: [])
    monkeypatch.setattr(manager, "_has_root_privileges", lambda: True)
    monkeypatch.setattr(manager, "_interface_exists", lambda interface: True)
    monkeypatch.setattr(manager, "_ensure_nftables_rule", lambda rule: "10")
    first = manager.apply_source("10.0.0.2", "10.0.0.1", "lo", "test")
    second = manager.apply_source("10.0.0.2", "10.0.0.1", "lo", "test again")
    assert first["success"] is True
    assert second["reused"] is True
    assert len(manager.rules) == 1


def test_live_source_rule_expiration_is_encoded_for_restart_cleanup(monkeypatch):
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables", "rule_ttl_seconds": 60})
    monkeypatch.setattr(manager, "_is_linux", lambda: True)
    monkeypatch.setattr(manager, "_tool_available", lambda tool: True)
    monkeypatch.setattr(manager, "_has_root_privileges", lambda: True)
    monkeypatch.setattr(manager, "_interface_exists", lambda interface: True)
    monkeypatch.setattr(manager, "_ensure_nftables_rule", lambda rule: "10")
    result = manager.apply_source("10.0.0.2", "10.0.0.1", "lo", "test")
    assert result["success"] is True
    rule = manager.rules[0]
    assert rule.expires_at is not None
    assert 59 <= (rule.expires_at - rule.created_at).total_seconds() <= 61
    assert manager._rule_id_expired(rule.rule_id, rule.expires_at)


def test_cleanup_expired_at_exact_expiration_removes_only_owned_rule(monkeypatch):
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    monkeypatch.setattr(manager, "_is_linux", lambda: True)
    monkeypatch.setattr(manager, "_tool_available", lambda tool: True)
    monkeypatch.setattr(manager, "_discover_nft_application_rules", lambda: [])
    removed = []
    monkeypatch.setattr(manager, "_remove_nftables_rule", lambda rule: removed.append(rule.rule_id) or {"success": True, "removed": True, "rule_id": rule.rule_id})
    rule = MitigationRule(
        rule_id="source-live-1700000000-abcdef123456",
        rule_type="nftables",
        target="10.0.0.1",
        interface="lo",
        reason="test",
        match="saddr",
        source_ip="10.0.0.2",
        expires_at=datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc),
    )
    manager.rules.append(rule)
    assert manager.cleanup_expired(now=rule.expires_at) == [rule.rule_id]
    assert removed == [rule.rule_id]
    assert manager.rules == []


def test_discovery_requires_exact_owned_comment(monkeypatch):
    class Completed:
        returncode = 0
        stdout = json.dumps({
            "nftables": [
                {"rule": {"table": "ddos_detector", "chain": "input", "handle": 1, "comment": "ddos_detector:live-1"}},
                {"rule": {"table": "ddos_detector", "chain": "input", "handle": 2, "comment": "ddos_detector:live-1-extra:collision"}},
                {"rule": {"table": "ddos_detector", "chain": "input", "handle": 3, "comment": "other_ddos_detector:live-2"}},
            ]
        })
        stderr = ""

    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._is_linux", lambda self: True)
    monkeypatch.setattr("ddos_detector.mitigation.MitigationManager._tool_available", lambda self, tool: True)
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    assert [item["rule_id"] for item in manager._discover_nft_application_rules()] == ["live-1"]


def test_invalid_source_never_reaches_firewall(monkeypatch):
    manager = MitigationManager({"enabled": True, "dry_run": True, "mechanism": "nftables"})
    monkeypatch.setattr(manager, "_is_linux", lambda: False)
    result = manager.apply_source("not-an-ip", "127.0.0.1", "lo", "invalid")
    assert result["error"] == "invalid_source"


def test_cleanup_all_retains_local_rule_when_firewall_removal_fails(monkeypatch):
    manager = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables"})
    monkeypatch.setattr(manager, "_is_linux", lambda: True)
    monkeypatch.setattr(manager, "_tool_available", lambda tool: True)
    monkeypatch.setattr(manager, "_discover_nft_application_rules", lambda: [])
    monkeypatch.setattr(
        manager,
        "_remove_nftables_rule",
        lambda rule: {"success": False, "error": "cleanup_failed", "message": "permission denied"},
    )
    rule = MitigationRule(
        rule_id="live-1700000000-abcdef123456",
        rule_type="nftables",
        target="10.0.0.1",
        interface="veth0",
        reason="test cleanup error",
        backend_id="42",
    )
    manager.rules.append(rule)

    assert manager.cleanup_all() == []
    assert manager.rules == [rule]
    assert manager.last_cleanup_error["message"] == "permission denied"
