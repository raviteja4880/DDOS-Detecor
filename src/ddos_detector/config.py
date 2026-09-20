from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any, Dict
import logging

try:
    import yaml
except Exception:  # PyYAML may not be installed in CI; allow fallback to defaults
    yaml = None


@dataclass
class Config:
    interface: str = "lo"
    window_seconds: int = 5
    slide_seconds: int = 1
    capture: Dict[str, Any] = field(default_factory=lambda: {"bpf_filter": "", "snaplen": 262144})
    weights: Dict[str, float] = field(default_factory=lambda: {"syn_rate": 1.0, "packet_rate": 0.8, "distributed_source": 1.0, "connection_rate": 0.7, "dest_concentration": 0.5})
    thresholds: Dict[str, float] = field(default_factory=lambda: {"normal": 0.2, "suspicious": 0.6})
    logging: Dict[str, Any] = field(default_factory=lambda: {"level": "INFO", "json": False})
    baseline: Dict[str, Any] = field(default_factory=lambda: {"history_windows": 60, "minimum_samples": 10})
    detection: Dict[str, Any] = field(default_factory=lambda: {"minimum_indicators": 2, "minimum_consecutive_windows": 1})
    scoring: Dict[str, Any] = field(default_factory=lambda: {"weights": {"syn_rate": 1.0, "packet_rate": 0.8, "distributed_source": 1.0, "connection_rate": 0.7, "dest_concentration": 0.5}, "thresholds": {"normal": 0.2, "suspicious": 0.6}})
    simulation: Dict[str, Any] = field(default_factory=lambda: {"enabled": True, "mode": "normal", "rate_limit": 1000, "packet_limit": 50000, "target": "127.0.0.1", "max_sources": 20})
    alerts: Dict[str, Any] = field(default_factory=lambda: {"enabled": True, "console": True, "structured_logging": True, "email": {"enabled": False, "provider": "brevo", "cooldown_seconds": 60}})
    mitigation: Dict[str, Any] = field(default_factory=lambda: {"enabled": False, "dry_run": True, "mechanism": "nftables", "rule_ttl_seconds": 60, "auto_block_sources": False, "max_auto_block_sources": 5})


DEFAULT_CAPTURE = {"bpf_filter": "", "snaplen": 262144}
DEFAULT_WEIGHTS = {"syn_rate": 1.0, "packet_rate": 0.8, "distributed_source": 1.0, "connection_rate": 0.7, "dest_concentration": 0.5}
DEFAULT_THRESHOLDS = {"normal": 0.2, "suspicious": 0.6}
DEFAULT_LOGGING = {"level": "INFO", "json": False}
DEFAULT_BASELINE = {"history_windows": 60, "minimum_samples": 10}
DEFAULT_DETECTION = {"minimum_indicators": 2, "minimum_consecutive_windows": 1}
DEFAULT_SCORING = {"weights": DEFAULT_WEIGHTS.copy(), "thresholds": DEFAULT_THRESHOLDS.copy()}
DEFAULT_SIMULATION = {"enabled": True, "mode": "normal", "rate_limit": 1000, "packet_limit": 50000, "target": "127.0.0.1", "max_sources": 20}
DEFAULT_ALERTS = {"enabled": True, "console": True, "structured_logging": True, "email": {"enabled": False, "provider": "brevo", "cooldown_seconds": 60}}
DEFAULT_MITIGATION = {"enabled": False, "dry_run": True, "mechanism": "nftables", "rule_ttl_seconds": 60, "auto_block_sources": False, "max_auto_block_sources": 5}


def _is_safe_local_target(target: str) -> bool:
    value = str(target or "").strip()
    if not value or value.lower() in {"localhost"}:
        return True
    try:
        addr = ip_address(value)
    except ValueError:
        return False
    if addr.version == 6:
        return str(addr) in {"::1"}
    if addr.is_private or addr.is_loopback:
        return True
    return False


def validate_config(cfg: Config) -> Config:
    if not isinstance(cfg.interface, str) or not cfg.interface.strip():
        raise ValueError("Configuration error: interface must be a non-empty string")
    if not isinstance(cfg.window_seconds, int) or cfg.window_seconds <= 0:
        raise ValueError("Configuration error: window_seconds must be a positive integer")
    if not isinstance(cfg.slide_seconds, int) or cfg.slide_seconds <= 0:
        raise ValueError("Configuration error: slide_seconds must be a positive integer")
    if cfg.slide_seconds > cfg.window_seconds:
        raise ValueError("Configuration error: slide_seconds cannot be greater than window_seconds")
    if cfg.capture is None:
        cfg.capture = DEFAULT_CAPTURE.copy()
    if not isinstance(cfg.capture.get("snaplen", 0), int) or cfg.capture.get("snaplen", 0) <= 0:
        raise ValueError("Configuration error: capture.snaplen must be a positive integer")
    if cfg.capture.get("snaplen", 0) > 1048576:
        raise ValueError("Configuration error: capture.snaplen exceeds the safe maximum of 1048576")
    if cfg.logging is None:
        cfg.logging = DEFAULT_LOGGING.copy()
    if not isinstance(cfg.logging.get("level", "INFO"), str):
        raise ValueError("Configuration error: logging.level must be a string")
    if not isinstance(cfg.logging.get("json", False), bool):
        raise ValueError("Configuration error: logging.json must be boolean")
    if cfg.baseline is None:
        cfg.baseline = DEFAULT_BASELINE.copy()
    if cfg.detection is None:
        cfg.detection = DEFAULT_DETECTION.copy()
    if cfg.scoring is None:
        cfg.scoring = DEFAULT_SCORING.copy()
    if cfg.simulation is None:
        cfg.simulation = DEFAULT_SIMULATION.copy()
    if cfg.alerts is None:
        cfg.alerts = DEFAULT_ALERTS.copy()
    if cfg.mitigation is None:
        cfg.mitigation = DEFAULT_MITIGATION.copy()

    baseline_history = int(cfg.baseline.get("history_windows", DEFAULT_BASELINE["history_windows"]))
    minimum_samples = int(cfg.baseline.get("minimum_samples", DEFAULT_BASELINE["minimum_samples"]))
    if baseline_history <= 0 or baseline_history > 10000:
        raise ValueError("Configuration error: baseline.history_windows must be between 1 and 10000")
    if minimum_samples <= 0 or minimum_samples > baseline_history:
        raise ValueError("Configuration error: baseline.minimum_samples must be between 1 and history_windows")

    detection_min = int(cfg.detection.get("minimum_indicators", DEFAULT_DETECTION["minimum_indicators"]))
    detection_consecutive = int(cfg.detection.get("minimum_consecutive_windows", DEFAULT_DETECTION["minimum_consecutive_windows"]))
    if detection_min <= 0 or detection_min > 10:
        raise ValueError("Configuration error: detection.minimum_indicators must be between 1 and 10")
    if detection_consecutive <= 0 or detection_consecutive > 20:
        raise ValueError("Configuration error: detection.minimum_consecutive_windows must be between 1 and 20")

    thresholds = cfg.thresholds or DEFAULT_THRESHOLDS
    if not isinstance(thresholds, dict):
        raise ValueError("Configuration error: thresholds must be a dictionary")
    normal_threshold = float(thresholds.get("normal", DEFAULT_THRESHOLDS["normal"]))
    suspicious_threshold = float(thresholds.get("suspicious", DEFAULT_THRESHOLDS["suspicious"]))
    if not (0.0 < normal_threshold < 1.0):
        raise ValueError("Configuration error: thresholds.normal must be between 0 and 1")
    if not (0.0 < suspicious_threshold < 1.0):
        raise ValueError("Configuration error: thresholds.suspicious must be between 0 and 1")
    if suspicious_threshold <= normal_threshold:
        raise ValueError("Configuration error: thresholds.suspicious must be greater than thresholds.normal")

    weights = cfg.weights or DEFAULT_WEIGHTS
    if not isinstance(weights, dict):
        raise ValueError("Configuration error: weights must be a dictionary")
    for key, value in weights.items():
        if not isinstance(value, (int, float)) or value <= 0 or not (0 < float(value) < 1e9):
            raise ValueError(f"Configuration error: weights.{key} must be a positive finite number")

    simulation_cfg = cfg.simulation or DEFAULT_SIMULATION
    if not isinstance(simulation_cfg.get("enabled", True), bool):
        raise ValueError("Configuration error: simulation.enabled must be boolean")
    mode = str(simulation_cfg.get("mode", "normal"))
    if mode not in {"normal", "distributed"}:
        raise ValueError("Configuration error: simulation.mode must be 'normal' or 'distributed'")
    rate_limit = int(simulation_cfg.get("rate_limit", DEFAULT_SIMULATION["rate_limit"]))
    packet_limit = int(simulation_cfg.get("packet_limit", DEFAULT_SIMULATION["packet_limit"]))
    max_sources = int(simulation_cfg.get("max_sources", DEFAULT_SIMULATION["max_sources"]))
    if rate_limit <= 0 or rate_limit > 20000:
        raise ValueError("Configuration error: simulation.rate_limit must be between 1 and 20000")
    if packet_limit <= 0 or packet_limit > 500000:
        raise ValueError("Configuration error: simulation.packet_limit must be between 1 and 500000")
    if max_sources <= 0 or max_sources > 500:
        raise ValueError("Configuration error: simulation.max_sources must be between 1 and 500")
    target = str(simulation_cfg.get("target", DEFAULT_SIMULATION["target"]))
    if not _is_safe_local_target(target):
        raise ValueError("Configuration error: simulation.target must be localhost or a private/lab IPv4/IPv6 address")

    if not isinstance(cfg.alerts.get("enabled", True), bool):
        raise ValueError("Configuration error: alerts.enabled must be boolean")
    if not isinstance(cfg.mitigation.get("enabled", False), bool):
        raise ValueError("Configuration error: mitigation.enabled must be boolean")
    if not isinstance(cfg.mitigation.get("dry_run", True), bool):
        raise ValueError("Configuration error: mitigation.dry_run must be boolean")
    if cfg.mitigation.get("enabled", False) and not cfg.mitigation.get("dry_run", True):
        logging.warning("Live mitigation is enabled; this may modify system state and should be used only on a lab or isolated environment.")
    mechanism = str(cfg.mitigation.get("mechanism", DEFAULT_MITIGATION["mechanism"]))
    if mechanism not in {"nftables", "tc"}:
        raise ValueError("Configuration error: mitigation.mechanism must be 'nftables' or 'tc'")
    ttl = int(cfg.mitigation.get("rule_ttl_seconds", DEFAULT_MITIGATION["rule_ttl_seconds"]))
    if ttl <= 0 or ttl > 86400:
        raise ValueError("Configuration error: mitigation.rule_ttl_seconds must be between 1 and 86400")
    if not isinstance(cfg.mitigation.get("auto_block_sources", False), bool):
        raise ValueError("Configuration error: mitigation.auto_block_sources must be boolean")
    max_auto = int(cfg.mitigation.get("max_auto_block_sources", DEFAULT_MITIGATION["max_auto_block_sources"]))
    if max_auto <= 0 or max_auto > 100:
        raise ValueError("Configuration error: mitigation.max_auto_block_sources must be between 1 and 100")
    return cfg


def load_config(path: str) -> Config:
    """Load YAML config if available, otherwise return defaults."""
    cfg = Config()
    try:
        if yaml is not None:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        else:
            raw = {}
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        k, v = line.split(":", 1)
                        raw[k.strip()] = v.strip().strip('"')
        cfg.interface = raw.get("interface", cfg.interface)
        cfg.window_seconds = int(raw.get("window_seconds", cfg.window_seconds))
        cfg.slide_seconds = int(raw.get("slide_seconds", cfg.slide_seconds))
        cfg.capture = raw.get("capture", DEFAULT_CAPTURE)
        cfg.weights = raw.get("weights", DEFAULT_WEIGHTS)
        cfg.thresholds = raw.get("thresholds", DEFAULT_THRESHOLDS)
        cfg.logging = raw.get("logging", DEFAULT_LOGGING)
        cfg.baseline = raw.get("baseline", DEFAULT_BASELINE)
        cfg.detection = raw.get("detection", DEFAULT_DETECTION)
        cfg.scoring = raw.get("scoring", DEFAULT_SCORING)
        cfg.simulation = raw.get("simulation", DEFAULT_SIMULATION)
        cfg.alerts = raw.get("alerts", DEFAULT_ALERTS)
        cfg.mitigation = raw.get("mitigation", DEFAULT_MITIGATION)
    except FileNotFoundError:
        logging.warning("Config file %s not found, using defaults", path)
        cfg.capture = DEFAULT_CAPTURE.copy()
        cfg.weights = DEFAULT_WEIGHTS.copy()
        cfg.thresholds = DEFAULT_THRESHOLDS.copy()
        cfg.logging = DEFAULT_LOGGING.copy()
        cfg.baseline = DEFAULT_BASELINE.copy()
        cfg.detection = DEFAULT_DETECTION.copy()
        cfg.scoring = DEFAULT_SCORING.copy()
        cfg.simulation = DEFAULT_SIMULATION.copy()
        cfg.alerts = DEFAULT_ALERTS.copy()
        cfg.mitigation = DEFAULT_MITIGATION.copy()
    except (TypeError, ValueError, OSError) as exc:
        raise ValueError(f"Configuration file could not be parsed: {exc}") from exc
    return validate_config(cfg)
