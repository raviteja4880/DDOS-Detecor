from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
NFT_COMMAND_TIMEOUT_SECONDS = 5


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
    excluded_sources: List[str] = field(default_factory=list)
    attributable_sources: List[str] = field(default_factory=list)
    shared_source_networks: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
    ])
    repeated_offender: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "initial_ttl_seconds": 60,
        "escalation_factor": 2.0,
        "max_ttl_seconds": 300,
        "history_ttl_seconds": 3600,
        "max_history_entries": 100,
    })

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
        excluded = self.excluded_sources or []
        if not isinstance(excluded, list):
            raise ValueError("mitigation.excluded_sources must be a list of IPv4/IPv6 addresses or networks")
        for value in excluded:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("mitigation.excluded_sources entries must be non-empty strings")
            candidate = value.strip()
            try:
                ip_address(candidate)
            except ValueError:
                try:
                    ip_network(candidate, strict=False)
                except ValueError as exc:
                    raise ValueError(f"mitigation.excluded_sources contains invalid entry: {candidate}") from exc
        for field_name, values in (
            ("attributable_sources", self.attributable_sources or []),
            ("shared_source_networks", self.shared_source_networks or []),
        ):
            if not isinstance(values, list):
                raise ValueError(f"mitigation.{field_name} must be a list of IPv4/IPv6 addresses or networks")
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"mitigation.{field_name} entries must be non-empty strings")
                candidate = value.strip()
                try:
                    ip_address(candidate)
                except ValueError:
                    try:
                        ip_network(candidate, strict=False)
                    except ValueError as exc:
                        raise ValueError(f"mitigation.{field_name} contains invalid entry: {candidate}") from exc
        policy = self.repeated_offender or {}
        if not isinstance(policy.get("enabled", True), bool):
            raise ValueError("mitigation.repeated_offender.enabled must be boolean")
        initial = int(policy.get("initial_ttl_seconds", self.rule_ttl_seconds))
        maximum = int(policy.get("max_ttl_seconds", max(initial, self.rule_ttl_seconds)))
        history_ttl = int(policy.get("history_ttl_seconds", 3600))
        max_history = int(policy.get("max_history_entries", 100))
        factor = float(policy.get("escalation_factor", 2.0))
        if initial <= 0 or maximum < initial or maximum > 86400:
            raise ValueError("mitigation.repeated_offender TTL values are invalid")
        if factor < 1.0 or factor > 10.0:
            raise ValueError("mitigation.repeated_offender.escalation_factor must be between 1 and 10")
        if history_ttl <= 0 or history_ttl > 604800:
            raise ValueError("mitigation.repeated_offender.history_ttl_seconds must be between 1 and 604800")
        if max_history <= 0 or max_history > 1000:
            raise ValueError("mitigation.repeated_offender.max_history_entries must be between 1 and 1000")


class MitigationManager:
    TABLE_NAME = "ddos_detector"
    CHAIN_NAME = "input"
    FAMILY = "inet"
    OWNED_COMMENT_RE = re.compile(
        r"^ddos_detector:((?:source-)?live-[A-Za-z0-9][A-Za-z0-9_-]{0,127}|dryrun-[A-Za-z0-9][A-Za-z0-9_-]{0,127})$"
    )

    def __init__(self, config: Dict[str, Any] | MitigationConfig | None = None):
        if config is None:
            config = {"enabled": False, "dry_run": True, "mechanism": "nftables", "rule_ttl_seconds": 60, "max_rules": 20}
        if isinstance(config, MitigationConfig):
            self.config = config
        else:
            self.config = MitigationConfig(**{**{"enabled": False, "dry_run": True, "mechanism": "nftables", "rule_ttl_seconds": 60, "max_rules": 20}, **config})
        self.config.validate()
        self.rules: List[MitigationRule] = []
        self.offender_history: Dict[tuple[str, str, str], Dict[str, Any]] = {}
        self.last_cleanup_error: Optional[Dict[str, Any]] = None
        self.audit_log: List[Dict[str, Any]] = []

    def _record_audit(self, *, event: str, source: str | None, target: str | None, interface: str | None, reason: str, classification: str | None = None, score: float | None = None, rule_id: str | None = None, action: str, status: str, expiration: datetime | None = None) -> Dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "source": source,
            "target": target,
            "interface": interface,
            "reason": reason,
            "classification": classification,
            "score": score,
            "rule_id": rule_id,
            "action": action,
            "status": status,
            "expiration": expiration.isoformat() if expiration else None,
        }
        self.audit_log.append(record)
        if len(self.audit_log) > 200:
            self.audit_log = self.audit_log[-200:]
        return record

    def _source_is_excluded(self, source_ip: str) -> bool:
        if not source_ip:
            return False
        excluded = getattr(self.config, "excluded_sources", []) or []
        try:
            candidate = ip_address(source_ip)
        except ValueError:
            return False
        for entry in excluded:
            if not entry:
                continue
            if entry == source_ip:
                return True
            try:
                if candidate.version == ip_address(entry).version and candidate in ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def assess_source_attribution(self, source_ip: str) -> Dict[str, Any]:
        """Return a conservative attribution decision for automatic source blocking."""
        try:
            candidate = ip_address(source_ip)
        except ValueError:
            return {
                "attributable": False,
                "shared_or_nat": False,
                "reason": "Source IP is invalid and cannot be attributed.",
            }
        if self._source_is_excluded(source_ip):
            return {
                "attributable": False,
                "shared_or_nat": False,
                "reason": "Source IP is trusted or excluded from automatic mitigation.",
            }
        for entry in self.config.attributable_sources or []:
            try:
                network = ip_network(entry, strict=False)
                if candidate.version == network.version and candidate in network:
                    return {
                        "attributable": True,
                        "shared_or_nat": False,
                        "reason": "Source IP is explicitly configured as attributable.",
                    }
            except ValueError:
                continue
        for entry in self.config.shared_source_networks or []:
            try:
                network = ip_network(entry, strict=False)
                if candidate.version == network.version and candidate in network:
                    return {
                        "attributable": False,
                        "shared_or_nat": True,
                        "reason": "Source IP is in a configured shared/NAT network.",
                    }
            except ValueError:
                continue
        return {
            "attributable": False,
            "shared_or_nat": True,
            "reason": "Network metadata cannot safely distinguish this source from shared/NAT traffic.",
        }

    def _repeated_policy(self) -> Dict[str, Any]:
        return self.config.repeated_offender or {}

    def _source_rule_id(self, source_ip: str, target: str, interface: str) -> str:
        safe_source = source_ip.replace(":", "_").replace(".", "_")
        safe_target = target.replace(":", "_").replace(".", "_")
        safe_interface = interface.replace("-", "_")
        return f"source-{safe_source}-{safe_target}-{safe_interface}"

    def _source_key(self, source_ip: str, target: str, interface: str) -> tuple[str, str, str]:
        return source_ip, target, interface

    def _prune_history(self, now: datetime) -> None:
        policy = self._repeated_policy()
        history_ttl = int(policy.get("history_ttl_seconds", 3600))
        expired = [
            key for key, entry in self.offender_history.items()
            if now - entry["last_block_time"] >= timedelta(seconds=history_ttl)
            and not entry.get("current_blocked", False)
        ]
        for key in expired:
            del self.offender_history[key]
        max_entries = int(policy.get("max_history_entries", 100))
        if len(self.offender_history) > max_entries:
            oldest = sorted(self.offender_history, key=lambda key: self.offender_history[key]["last_block_time"])
            for key in oldest[: len(self.offender_history) - max_entries]:
                if not self.offender_history[key].get("current_blocked", False):
                    del self.offender_history[key]

    def _source_ttl(self, block_count: int) -> int:
        policy = self._repeated_policy()
        initial = int(policy.get("initial_ttl_seconds", self.config.rule_ttl_seconds))
        maximum = int(policy.get("max_ttl_seconds", initial))
        factor = float(policy.get("escalation_factor", 2.0))
        return min(maximum, max(initial, int(initial * (factor ** max(0, block_count - 1)))))

    def _new_rule_id(self, source: bool, expires_at: datetime) -> str:
        prefix = "source-live" if source else "live"
        return f"{prefix}-{int(expires_at.timestamp())}-{uuid.uuid4().hex[:12]}"

    @staticmethod
    def _rule_id_expired(rule_id: str, now: datetime) -> bool:
        match = re.search(r"(?:source-)?live-(\d+)-[0-9a-f]{12}$", rule_id)
        return bool(match and now.timestamp() >= int(match.group(1)))

    def _tool_available(self, tool: str) -> bool:
        binary = {"nftables": "nft", "tc": "tc"}.get(tool, tool)
        return shutil.which(binary) is not None

    def _is_linux(self) -> bool:
        return os.name == "posix" and platform.system() == "Linux"

    def _interface_exists(self, interface: str) -> bool:
        if not interface or not isinstance(interface, str):
            return False
        candidate = interface.strip()
        if (
            not candidate
            or candidate != interface
            or "/" in candidate
            or "\\" in candidate
            or candidate in {".", ".."}
        ):
            return False
        if os.path.isdir(f"/sys/class/net/{candidate}"):
            return True
        if_nametoindex = getattr(socket, "if_nametoindex", None)
        if not callable(if_nametoindex):
            return False
        try:
            return int(if_nametoindex(candidate)) > 0
        except (OSError, ValueError, TypeError):
            return False

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

    @classmethod
    def _owned_rule_id(cls, comment: Any) -> str | None:
        if not isinstance(comment, str):
            return None
        match = cls.OWNED_COMMENT_RE.fullmatch(comment)
        return match.group(1) if match else None

    def _nft_rule_handles(self, rule_id: str) -> List[str]:
        if not self._tool_available("nft"):
            return []
        try:
            result = self._run_nft_command(
                ["-j", "list", "chain", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME],
            )
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(f"Unable to inspect detector-owned nftables rules: {exc}") from exc
        if result.returncode != 0:
            stderr = (result.stderr or "").lower()
            if "no such file or directory" in stderr or "does not exist" in stderr:
                return []
            raise RuntimeError(
                "Unable to inspect detector-owned nftables rules: "
                f"{result.stderr.strip() or result.stdout.strip() or 'nft command failed'}"
            )
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("nft returned invalid JSON while inspecting owned rules") from exc
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
        try:
            result = subprocess.run(
                ["nft", *args],
                shell=False,
                capture_output=True,
                text=True,
                check=False,
                timeout=NFT_COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"nft command timed out after {NFT_COMMAND_TIMEOUT_SECONDS} seconds"
            ) from exc
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
            result = self._run_nft_command(
                ["delete", "rule", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME, "handle", str(handle)]
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": "cleanup_failed",
                    "rule_id": rule.rule_id,
                    "message": result.stderr.strip() or result.stdout.strip() or f"Failed to remove nftables rule handle {handle}",
                }
        return {"success": True, "removed": True, "rule_id": rule.rule_id, "message": "nftables rule removed"}

    def _rollback_partial_rule(self, rule: MitigationRule) -> None:
        if not rule.rule_id:
            return
        try:
            self._remove_nftables_rule(rule)
        except Exception:
            logger.exception("Failed to roll back partial nftables rule %s", rule.rule_id)

    def _discover_nft_application_rules(self) -> List[Dict[str, Any]]:
        if not self._is_linux() or not self._tool_available("nft"):
            return []
        result = self._run_nft_command(
            ["-j", "list", "chain", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME]
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").lower()
            if "no such file or directory" in stderr or "does not exist" in stderr:
                return []
            raise RuntimeError(
                "Unable to discover detector-owned nftables rules: "
                f"{result.stderr.strip() or result.stdout.strip() or 'nft command failed'}"
            )
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("nft returned invalid JSON while discovering owned rules") from exc

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
                rule_id = self._owned_rule_id(comment)
                if table == self.TABLE_NAME and chain == self.CHAIN_NAME and rule_id is not None:
                    handle = rule.get("handle")
                    if handle is None:
                        continue
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
                rule_id = self._owned_rule_id(comment)
                if rule_id is None:
                    continue
                handle = rule.get("handle")
                if handle is None:
                    continue
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
        for rule in self.rules:
            if rule.is_expired(now) and rule.source_ip:
                key = self._source_key(rule.source_ip, rule.target, rule.interface)
                entry = self.offender_history.get(key)
                if entry and entry.get("current_blocked"):
                    entry["current_blocked"] = False
                    entry["previous_expiration"] = entry["expires_at"]
        self.rules = [rule for rule in self.rules if not rule.is_expired(now)]
        for entry in self.offender_history.values():
            if entry.get("current_blocked") and entry["expires_at"] <= now:
                entry["current_blocked"] = False
                entry["previous_expiration"] = entry["expires_at"]
        self._prune_history(now)

    def _rule_limit_reached(self) -> bool:
        return len(self.rules) >= self.config.max_rules

    def dry_run_apply(self, target: str, interface: str, reason: str, source: bool = False, source_ip: str | None = None, ttl_seconds: int | None = None, rule_id: str | None = None, classification: str | None = None, score: float | None = None) -> Dict[str, Any]:
        self.validate_target(target, interface)
        self._prune_expired()
        rule = MitigationRule(
            rule_id=rule_id or f"dryrun-{len(self.rules)+1}",
            rule_type=self.config.mechanism,
            target=target,
            interface=interface,
            reason=reason,
            match=("saddr" if source else "daddr"),
            source_ip=source_ip,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds or self.config.rule_ttl_seconds),
            status="dry_run",
        )
        if self._rule_limit_reached():
            return {
                "success": False,
                "dry_run": True,
                "error": "rule_limit_reached",
                "message": "Maximum mitigation rules reached; no rule was created.",
            }
        self.rules.append(rule)
        self._record_audit(
            event="mitigation_applied",
            source=source_ip,
            target=target,
            interface=interface,
            reason=reason,
            classification=classification,
            score=score,
            rule_id=rule.rule_id,
            action="create",
            status="applied",
            expiration=rule.expires_at,
        )
        return {
            "success": True,
            "dry_run": True,
            "rule": rule.describe(),
            "message": "DRY RUN — no system network rules were modified.",
            "rule_id": rule.rule_id,
        }

    def apply(self, target: str, interface: str, reason: str, source: bool = False, source_ip: str | None = None, ttl_seconds: int | None = None, rule_id: str | None = None, classification: str | None = None, score: float | None = None) -> Dict[str, Any]:
        if not self.config.enabled:
            return {"success": False, "dry_run": True, "error": "mitigation_disabled", "message": "Mitigation disabled by configuration; no system rules changed."}
        if self.config.dry_run:
            return self.dry_run_apply(target, interface, reason, source=source, source_ip=source_ip, ttl_seconds=ttl_seconds, rule_id=rule_id, classification=classification, score=score)
        try:
            self.validate_target(target, interface)
        except ValueError as exc:
            return {"success": False, "dry_run": False, "error": "invalid_target", "message": str(exc)}
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
        if self._rule_limit_reached():
            return {
                "success": False,
                "dry_run": False,
                "error": "rule_limit_reached",
                "message": "Maximum mitigation rules reached; no rule was created.",
            }
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds or self.config.rule_ttl_seconds)
        rule = MitigationRule(
            rule_id=rule_id or self._new_rule_id(source, expires_at),
            rule_type=self.config.mechanism,
            target=target,
            interface=interface,
            reason=reason,
            match=("saddr" if source else "daddr"),
            source_ip=source_ip,
            expires_at=expires_at,
            status="active",
        )
        try:
            backend_id = self._ensure_nftables_rule(rule)
            rule.backend_id = backend_id
            self.rules.append(rule)
        except Exception as exc:  # pragma: no cover - defensive fallback
            self._rollback_partial_rule(rule)
            self._record_audit(
                event="mitigation_failed",
                source=source_ip,
                target=target,
                interface=interface,
                reason=reason,
                classification=classification,
                score=score,
                rule_id=rule.rule_id,
                action="create",
                status="failed",
                expiration=rule.expires_at,
            )
            return {"success": False, "dry_run": False, "error": "mitigation_failed", "message": f"Mitigation attempted but failed: {exc}"}
        self._record_audit(
            event="mitigation_applied",
            source=source_ip,
            target=target,
            interface=interface,
            reason=reason,
            classification=classification,
            score=score,
            rule_id=rule.rule_id,
            action="create",
            status="applied",
            expiration=rule.expires_at,
        )
        return {"success": True, "dry_run": False, "rule": rule.describe(), "message": "Live nftables mitigation rule added."}

    def apply_source(self, source_ip: str, target_ip: str, interface: str, reason: str, classification: str | None = None, score: float | None = None) -> Dict[str, Any]:
        """Apply a source-and-destination nftables rule for one detected source."""
        self.validate_target(target_ip, interface)
        try:
            ip_address(source_ip)
        except ValueError as exc:
            return {"success": False, "dry_run": self.config.dry_run, "error": "invalid_source", "message": "Source IP must be a valid IP address"}
        source_addr = ip_address(source_ip)
        if source_addr.is_global:
            return {"success": False, "dry_run": self.config.dry_run, "error": "public_source_rejected", "message": "Public source IPs are rejected"}
        if source_addr == ip_address(target_ip):
            return {"success": False, "dry_run": self.config.dry_run, "error": "source_target_conflict", "message": "Source and target IPs must be different"}
        if self._source_is_excluded(source_ip):
            self._record_audit(
                event="mitigation_excluded",
                source=source_ip,
                target=target_ip,
                interface=interface,
                reason=reason,
                classification=classification,
                score=score,
                rule_id=None,
                action="block",
                status="excluded",
                expiration=None,
            )
            return {"success": False, "dry_run": self.config.dry_run, "error": "source_excluded", "message": "Source IP is allowlisted and may not be auto-mitigated."}
        now = datetime.now(timezone.utc)
        self._prune_expired(now)
        policy = self._repeated_policy()
        if not policy.get("enabled", True):
            ttl = self.config.rule_ttl_seconds
            rule_id = None
        else:
            key = self._source_key(source_ip, target_ip, interface)
            entry = self.offender_history.get(key)
            active = next(
                (
                    rule for rule in self.rules
                    if rule.source_ip == source_ip
                    and rule.target == target_ip
                    and rule.interface == interface
                    and not rule.is_expired(now)
                ),
                None,
            )
            rule_id = active.rule_id if active else None
            if active is not None:
                self._record_audit(
                    event="mitigation_prevented",
                    source=source_ip,
                    target=target_ip,
                    interface=interface,
                    reason=reason,
                    classification=classification,
                    score=score,
                    rule_id=rule_id,
                    action="block",
                    status="duplicate",
                    expiration=active.expires_at if active else None,
                )
                return {"success": False, "dry_run": self.config.dry_run, "error": "already_blocked", "reused": True, "message": "Source is already actively mitigated; duplicate rule was not created.", "rule_id": rule_id}
            active_sources = {
                rule.source_ip for rule in self.rules
                if rule.match == "saddr" and not rule.is_expired(now) and rule.source_ip
            }
            if source_ip not in active_sources and len(active_sources) >= self.config.max_auto_block_sources:
                self._record_audit(
                    event="mitigation_prevented",
                    source=source_ip,
                    target=target_ip,
                    interface=interface,
                    reason=reason,
                    classification=classification,
                    score=score,
                    rule_id=rule_id,
                    action="block",
                    status="limit_reached",
                    expiration=None,
                )
                return {"success": False, "dry_run": self.config.dry_run, "error": "source_limit_reached", "message": "Maximum automatic source mitigations reached; no rule was created."}
            block_count = (entry or {}).get("block_count", 0) + 1
            ttl = self._source_ttl(block_count)
        result = self.apply(target_ip, interface, reason, source=True, source_ip=source_ip, ttl_seconds=ttl, rule_id=rule_id, classification=classification, score=score)
        if result.get("success") and policy.get("enabled", True):
            expires_at = now + timedelta(seconds=ttl)
            key = self._source_key(source_ip, target_ip, interface)
            self.offender_history[key] = {
                "source_ip": source_ip,
                "target": target_ip,
                "last_block_time": now,
                "block_count": (self.offender_history.get(key, {}).get("block_count", 0) + 1),
                "current_blocked": True,
                "expires_at": expires_at,
                "previous_expiration": (self.offender_history.get(key, {}).get("expires_at")),
            }
            self._prune_history(now)
        result["ttl_seconds"] = ttl
        return result

    def cleanup_expired(self, now: Optional[datetime] = None) -> List[str]:
        self.last_cleanup_error = None
        if now is None:
            now = datetime.now(timezone.utc)
        removed: List[str] = []
        remaining: List[MitigationRule] = []
        for rule in self.rules:
            if rule.is_expired(now):
                if rule.source_ip:
                    key = self._source_key(rule.source_ip, rule.target, rule.interface)
                    entry = self.offender_history.get(key)
                if (
                    not self.config.dry_run
                    and self.config.mechanism == "nftables"
                    and self._is_linux()
                    and self._tool_available("nft")
                ):
                    cleanup_result = self._remove_nftables_rule(rule)
                    if cleanup_result.get("success") is False:
                        self.last_cleanup_error = cleanup_result
                        remaining.append(rule)
                        continue
                if rule.source_ip:
                    entry = self.offender_history.get(key)
                    if entry and entry.get("current_blocked"):
                        entry["current_blocked"] = False
                        entry["previous_expiration"] = entry["expires_at"]
                removed.append(rule.rule_id)
            else:
                remaining.append(rule)
        if (
            not self.config.dry_run
            and self.config.mechanism == "nftables"
            and self._is_linux()
            and self._tool_available("nft")
        ):
            for rule_info in self._discover_nft_application_rules():
                rule_id = rule_info["rule_id"]
                if not self._rule_id_expired(rule_id, now):
                    continue
                result = self._run_nft_command(
                    ["delete", "rule", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME, "handle", str(rule_info["handle"])]
                )
                if result.returncode == 0 or "no such file" in (result.stderr or "").lower():
                    if rule_id not in removed:
                        removed.append(rule_id)
                else:
                    self.last_cleanup_error = {
                        "success": False,
                        "error": "cleanup_failed",
                        "rule_id": rule_id,
                        "message": result.stderr.strip() or result.stdout.strip() or f"Failed to remove nftables rule handle {rule_info['handle']}",
                    }
        self.rules = remaining
        for entry in self.offender_history.values():
            if entry.get("current_blocked") and entry["expires_at"] <= now:
                entry["current_blocked"] = False
                entry["previous_expiration"] = entry["expires_at"]
        self._prune_history(now)
        return removed

    def cleanup_all(self) -> List[str]:
        self.last_cleanup_error = None
        removed: List[str] = []
        remaining: List[MitigationRule] = []
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
                result = self._run_nft_command(
                    ["delete", "rule", self.FAMILY, self.TABLE_NAME, self.CHAIN_NAME, "handle", str(rule_info["handle"])]
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
                    remaining.append(rule)
                    continue
            removed.append(rule.rule_id)
        self.rules = remaining
        return removed
