from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any, Dict, List, Optional


@dataclass
class MitigationRule:
    rule_id: str
    rule_type: str
    target: str
    interface: str
    reason: str
    match: str = "daddr"  # 'daddr' for destination match, 'saddr' for source match
    source_ip: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    status: str = "active"
    backend_id: str | None = None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        if now is None:
            now = datetime.now(timezone.utc)
        return now >= self.expires_at

    def describe(self) -> str:
        return f"{self.rule_type} for {self.target} on {self.interface} (reason={self.reason})"


@dataclass
class MitigationConfig:
    enabled: bool = False
    dry_run: bool = True
    mechanism: str = "nftables"
    rule_ttl_seconds: int = 60
    max_rules: int = 20
    auto_block_sources: bool = False
    max_auto_block_sources: int = 5

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("mitigation.enabled must be boolean")
        if not isinstance(self.dry_run, bool):
            raise ValueError("mitigation.dry_run must be boolean")
        if self.mechanism not in {"nftables", "tc"}:
            raise ValueError("mitigation.mechanism must be 'nftables' or 'tc'")
        if self.rule_ttl_seconds <= 0 or self.rule_ttl_seconds > 86400:
            raise ValueError("mitigation.rule_ttl_seconds must be between 1 and 86400")
        if self.max_rules <= 0 or self.max_rules > 500:
            raise ValueError("mitigation.max_rules must be between 1 and 500")
        if not isinstance(self.auto_block_sources, bool):
            raise ValueError("mitigation.auto_block_sources must be boolean")
        if self.max_auto_block_sources <= 0 or self.max_auto_block_sources > 5:
            raise ValueError("mitigation.max_auto_block_sources must be between 1 and 5")


class MitigationManager:
    TABLE_NAME = "ddos_detector"
    CHAIN_NAME = "input"
    FAMILY = "inet"

    def __init__(self, config: Dict[str, Any] | MitigationConfig | None = None):
        if config is None:
            config = {"enabled": False, "dry_run": True, "mechanism": "nftables", "rule_ttl_seconds": 60, "max_rules": 20}
        if isinstance(config, MitigationConfig):
            self.config = config
        else:
            self.config = MitigationConfig(**{**{"enabled": False, "dry_run": True, "mechanism": "nftables", "rule_ttl_seconds": 60, "max_rules": 20}, **config})
        self.config.validate()
        self.rules: List[MitigationRule] = []
        self.last_cleanup_error: Optional[Dict[str, Any]] = None

    def _tool_available(self, tool: str) -> bool:
        binary = {"nftables": "nft", "tc": "tc"}.get(tool, tool)
        return shutil.which(binary) is not None

    def _is_linux(self) -> bool:
        return os.name == "posix" and platform.system() == "Linux"

    def _interface_exists(self, interface: str) -> bool:
        if not interface:
            return False
        return os.path.isdir(f"/sys/class/net/{interface}")

    def _has_root_privileges(self) -> bool:
        if os.name != "posix":
            return False
        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            return True
        return bool(geteuid() == 0)

    def _nft_comment(self, rule_id: str) -> str:
        return f"ddos_detector:{rule_id}"

    def _nft_comment_arg(self, rule_id: str) -> str:
        return f'"{self._nft_comment(rule_id)}"'

    def _nft_rule_handles(self, rule_id: str) -> List[str]:
        if not self._tool_available("nft"):
            return []
        result = subprocess.run(
            ["nft", "-j", "list", "chain", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return []
        handles: List[str] = []
        for entry in payload.get("nftables", []):
            if not isinstance(entry, dict):
                continue

            rule = entry.get("rule")
            if isinstance(rule, dict):
                if rule.get("table") != self.TABLE_NAME or rule.get("chain") != self.CHAIN_NAME:
                    continue
                comment = rule.get("comment")
                if comment == self._nft_comment(rule_id):
                    handle = rule.get("handle")
                    if handle is not None:
                        handles.append(str(handle))
                continue

            chain = entry.get("chain", {})
            if chain.get("table") != self.TABLE_NAME or chain.get("name") != self.CHAIN_NAME:
                continue
            for rule in chain.get("rules", []):
                comment = rule.get("comment")
                if comment == self._nft_comment(rule_id):
                    handle = rule.get("handle")
                    if handle is not None:
                        handles.append(str(handle))
        return handles

    def _run_nft_command(self, args: List[str], *, allow_exists: bool = False) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(["nft", *args], shell=False, capture_output=True, text=True, check=False)
        if allow_exists and result.returncode != 0:
            stderr = (result.stderr or "").lower()
            if "already exists" in stderr or "file exists" in stderr or "exists" in stderr:
                return result
        return result

    def _ensure_nftables_rule(self, rule: MitigationRule) -> str:
        if not self._tool_available("nft"):
            raise RuntimeError("nft binary not available")
        if not self._is_linux():
            raise RuntimeError("Live nftables mitigation is only supported on Linux")
        table_result = self._run_nft_command(["add", "table", self.FAMILY, self.TABLE_NAME], allow_exists=True)
        if table_result.returncode not in {0, 1}:
            raise RuntimeError(f"Failed to create nftables table: {table_result.stderr.strip() or table_result.stdout.strip()}")
        chain_args = [
            "add",
            "chain",
            self.FAMILY,
            self.TABLE_NAME,
            self.CHAIN_NAME,
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "0;",
            "policy",
            "accept;",
            "}",
        ]
        chain_result = self._run_nft_command(chain_args, allow_exists=True)
        if chain_result.returncode not in {0, 1}:
            raise RuntimeError(f"Failed to create nftables chain: {chain_result.stderr.strip() or chain_result.stdout.strip()}")

        rule_comment = self._nft_comment(rule.rule_id)
        rule_comment_arg = self._nft_comment_arg(rule.rule_id)
        add_rule = [
            "add",
            "rule",
            self.FAMILY,
            self.TABLE_NAME,
            self.CHAIN_NAME,
            "ip",
        ]
        if getattr(rule, "match", "daddr") == "saddr":
            add_rule.extend(["saddr", rule.source_ip or rule.target, "ip", "daddr", rule.target])
        else:
            add_rule.extend(["daddr", rule.target])
        add_rule.extend([
            "iifname",
            rule.interface,
            "drop",
            "comment",
            rule_comment_arg,
        ])
        add_result = self._run_nft_command(add_rule)
        if add_result.returncode != 0:
            raise RuntimeError(f"Failed to add nftables rule: {add_result.stderr.strip() or add_result.stdout.strip()}")
        handles = self._nft_rule_handles(rule.rule_id)
        if not handles:
            raise RuntimeError("nftables rule created but handle could not be resolved")
        return handles[0]

    def _remove_nftables_rule(self, rule: MitigationRule) -> Dict[str, Any]:
        handles = self._nft_rule_handles(rule.rule_id)
        if not handles:
            return {"success": True, "removed": False, "rule_id": rule.rule_id, "message": "No matching nftables rule found for this mitigation record."}
        for handle in handles:
            result = subprocess.run(
                ["nft", "delete", "rule", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME, "handle", str(handle)],
                shell=False,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": "cleanup_failed",
                    "rule_id": rule.rule_id,
                    "message": result.stderr.strip() or result.stdout.strip() or f"Failed to remove nftables rule handle {handle}",
                }
        return {"success": True, "removed": True, "rule_id": rule.rule_id, "message": "nftables rule removed"}

    def _discover_nft_application_rules(self) -> List[Dict[str, Any]]:
        if not self._is_linux() or not self._tool_available("nft"):
            return []
        result = subprocess.run(
            ["nft", "-j", "list", "chain", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return []

        discovered: List[Dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for entry in payload.get("nftables", []):
            if not isinstance(entry, dict):
                continue

            rule = entry.get("rule")
            if isinstance(rule, dict):
                table = rule.get("table")
                chain = rule.get("chain")
                comment = rule.get("comment")
                if table == self.TABLE_NAME and chain == self.CHAIN_NAME and isinstance(comment, str) and comment.startswith("ddos_detector:"):
                    handle = rule.get("handle")
                    if handle is None:
                        continue
                    rule_id = comment[len("ddos_detector:") :]
                    key = (rule_id, str(handle))
                    if key not in seen:
                        seen.add(key)
                        discovered.append({"rule_id": rule_id, "handle": str(handle), "comment": comment})
                continue

            chain = entry.get("chain", {})
            if chain.get("table") != self.TABLE_NAME or chain.get("name") != self.CHAIN_NAME:
                continue
            for rule in chain.get("rules", []):
                if not isinstance(rule, dict):
                    continue
                comment = rule.get("comment")
                if not isinstance(comment, str) or not comment.startswith("ddos_detector:"):
                    continue
                handle = rule.get("handle")
                if handle is None:
                    continue
                rule_id = comment[len("ddos_detector:") :]
                key = (rule_id, str(handle))
                if key not in seen:
                    seen.add(key)
                    discovered.append({"rule_id": rule_id, "handle": str(handle), "comment": comment})
        return discovered

    def validate_target(self, target: str, interface: str) -> None:
        if not target or not interface:
            raise ValueError("Mitigation target and interface are required")
        if target.startswith("http://") or target.startswith("https://"):
            raise ValueError("Mitigation requires a local or lab target, not a URL")
        try:
            addr = ip_address(target)
        except ValueError as exc:
            raise ValueError("Mitigation target must be a valid IP address") from exc
        if addr.is_global:
            raise ValueError("Mitigation target must be localhost or a private/lab IP address; public addresses are rejected")
        if not self._is_linux():
            return
        if not self._interface_exists(interface):
            raise ValueError(f"Linux interface '{interface}' does not exist")

    def _prune_expired(self, now: Optional[datetime] = None) -> None:
        if now is None:
            now = datetime.now(timezone.utc)
        self.rules = [rule for rule in self.rules if not rule.is_expired(now)]

    def _enforce_rule_limit(self) -> None:
        if len(self.rules) >= self.config.max_rules:
            self.rules = self.rules[-(self.config.max_rules - 1) :]

    def dry_run_apply(self, target: str, interface: str, reason: str, source: bool = False, source_ip: str | None = None) -> Dict[str, Any]:
        self.validate_target(target, interface)
        self._prune_expired()
        rule = MitigationRule(
            rule_id=f"dryrun-{len(self.rules)+1}",
            rule_type=self.config.mechanism,
            target=target,
            interface=interface,
            reason=reason,
            match=("saddr" if source else "daddr"),
            source_ip=source_ip,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.rule_ttl_seconds),
            status="dry_run",
        )
        self._enforce_rule_limit()
        self.rules.append(rule)
        return {
            "success": True,
            "dry_run": True,
            "rule": rule.describe(),
            "message": "DRY RUN — no system network rules were modified.",
            "rule_id": rule.rule_id,
        }

    def apply(self, target: str, interface: str, reason: str, source: bool = False, source_ip: str | None = None) -> Dict[str, Any]:
        if not self.config.enabled:
            return {"success": False, "dry_run": True, "error": "mitigation_disabled", "message": "Mitigation disabled by configuration; no system rules changed."}
        if self.config.dry_run:
            return self.dry_run_apply(target, interface, reason, source=source, source_ip=source_ip)
        try:
            self.validate_target(target, interface)
        except ValueError as exc:
            return {"success": False, "dry_run": False, "error": "invalid_target", "message": str(exc)}
        if os.name == "nt":
            return {"success": False, "dry_run": True, "error": "unsupported_platform", "message": "Linux mitigation tools are unavailable on this platform."}
        if not self._is_linux():
            return {"success": False, "dry_run": True, "error": "unsupported_platform", "message": "Live mitigation is only supported on Linux."}
        if self.config.mechanism != "nftables":
            return {"success": False, "dry_run": False, "error": "unsupported_mechanism", "message": "The tc backend is not implemented safely in this project; only nftables is supported for live Linux mitigation."}
        tool_name = "nft" if self.config.mechanism == "nftables" else self.config.mechanism
        if not self._tool_available(tool_name):
            return {"success": False, "dry_run": False, "error": "missing_dependency", "message": f"Linux mitigation tool not found: {tool_name}"}
        if not self._has_root_privileges():
            return {"success": False, "dry_run": False, "error": "insufficient_privileges", "message": "Live mitigation requires root privileges on Linux."}
        self._prune_expired()
        rule = MitigationRule(
            rule_id=f"source-live-{len(self.rules)+1}" if source else f"live-{len(self.rules)+1}",
            rule_type=self.config.mechanism,
            target=target,
            interface=interface,
            reason=reason,
            match=("saddr" if source else "daddr"),
            source_ip=source_ip,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.rule_ttl_seconds),
            status="active",
        )
        try:
            backend_id = self._ensure_nftables_rule(rule)
            rule.backend_id = backend_id
            self._enforce_rule_limit()
            self.rules.append(rule)
        except Exception as exc:  # pragma: no cover - defensive fallback
            return {"success": False, "dry_run": False, "error": "mitigation_failed", "message": str(exc)}
        return {"success": True, "dry_run": False, "rule": rule.describe(), "message": "Live nftables mitigation rule added."}

    def apply_source(self, source_ip: str, target_ip: str, interface: str, reason: str) -> Dict[str, Any]:
        """Apply a source-and-destination nftables rule for one detected source."""
        self.validate_target(target_ip, interface)
        try:
            ip_address(source_ip)
        except ValueError as exc:
            return {"success": False, "dry_run": self.config.dry_run, "error": "invalid_source", "message": "Source IP must be a valid IP address"}
        source_addr = ip_address(source_ip)
        if source_addr.is_global:
            return {"success": False, "dry_run": self.config.dry_run, "error": "public_source_rejected", "message": "Public source IPs are rejected"}
        return self.apply(target_ip, interface, reason, source=True, source_ip=source_ip)

    def cleanup_expired(self, now: Optional[datetime] = None) -> List[str]:
        if now is None:
            now = datetime.now(timezone.utc)
        removed: List[str] = []
        remaining: List[MitigationRule] = []
        for rule in self.rules:
            if rule.is_expired(now):
                if self.config.mechanism == "nftables" and self._is_linux() and self._tool_available("nft"):
                    cleanup_result = self._remove_nftables_rule(rule)
                    if cleanup_result.get("success") is False:
                        self.last_cleanup_error = cleanup_result
                        remaining.append(rule)
                        continue
                removed.append(rule.rule_id)
            else:
                remaining.append(rule)
        self.rules = remaining
        return removed

    def cleanup_all(self) -> List[str]:
        removed: List[str] = []
        self.last_cleanup_error = None
        discovered: List[Dict[str, Any]] = []
        if self.config.mechanism == "nftables" and self._is_linux() and self._tool_available("nft"):
            discovered = self._discover_nft_application_rules()
            seen_rule_ids: set[str] = set()
            for rule_info in discovered:
                rule_id = rule_info["rule_id"]
                if rule_id in seen_rule_ids:
                    continue
                seen_rule_ids.add(rule_id)
                result = subprocess.run(
                    ["nft", "delete", "rule", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME, "handle", str(rule_info["handle"])],
                    shell=False,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    self.last_cleanup_error = {
                        "success": False,
                        "error": "cleanup_failed",
                        "rule_id": rule_id,
                        "message": result.stderr.strip() or result.stdout.strip() or f"Failed to remove nftables rule handle {rule_info['handle']}",
                    }
                    continue
                removed.append(rule_id)

        for rule in list(self.rules):
            if rule.rule_id in removed:
                continue
            if self.config.mechanism == "nftables" and self._is_linux() and self._tool_available("nft"):
                cleanup_result = self._remove_nftables_rule(rule)
                if cleanup_result.get("success") is False:
                    self.last_cleanup_error = cleanup_result
                    continue
            removed.append(rule.rule_id)
        self.rules = []
        return removed
