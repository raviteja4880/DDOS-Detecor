import sys
import pathlib
import json

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.mitigation import MitigationManager, MitigationRule


def test_nft_rule_uses_saddr(monkeypatch):
    mgr = MitigationManager({"enabled": True, "dry_run": False, "mechanism": "nftables", "rule_ttl_seconds": 60})

    # force linux/tool checks to pass
    monkeypatch.setattr(mgr, '_tool_available', lambda tool: True)
    monkeypatch.setattr(mgr, '_is_linux', lambda: True)

    captured = {"add_rule_args": None}

    def fake_subprocess_run(cmd, shell=False, capture_output=False, text=False, check=False):
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
