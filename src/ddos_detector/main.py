"""CLI entrypoint for the passive DDoS detector.

The project stays defensive by default: it can run simulations and dry-run
alerting/mitigation flows without altering the host system unless explicitly
enabled in configuration.
"""
import argparse
import hashlib
import json
import logging
import os
import platform
import sys
import time
from collections import deque
from contextlib import contextmanager

from .alerts import mark_normal_window, maybe_emit_alert
from .aggregator import SlidingWindowAggregator
from .baseline import BaselineEngine
from .config import load_config
from .detector import analyze_window
from .logging_config import setup_logging
from .mitigation import MitigationManager
from .models import WindowMetric
from .packet_capture import open_capture
from .feature_extractor import extract_features
from .scoring import score_and_classify
from .simulator import simulate_window, validate_simulation_config

MITIGATION_CLEANUP_INTERVAL_SECONDS = 5.0
logger = logging.getLogger(__name__)


@contextmanager
def _monitor_instance_lock(interface):
    """Allow only one active monitor process per interface on Linux."""
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - monitor is Linux-only
        if not sys.platform.startswith("linux"):
            yield
            return
        raise RuntimeError("OS-level monitor singleton locking is unavailable.") from exc

    lock_dir = os.environ.get("DDOS_DETECTOR_LOCK_DIR", "/tmp")
    lock_name = hashlib.sha256(str(interface).encode("utf-8")).hexdigest()[:16]
    lock_path = os.path.join(lock_dir, f"ddos_detector_{lock_name}.lock")
    try:
        lock_file = open(lock_path, "a+", encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Unable to create monitor lock for interface '{interface}': {exc}") from exc

    try:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                f"Another detector is already monitoring interface '{interface}'."
            ) from exc
        lock_file.seek(0)
        lock_file.truncate()
        lock_file.write(f"pid={os.getpid()} interface={interface}\n")
        lock_file.flush()
        yield
    finally:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()


def build_parser():
    parser = argparse.ArgumentParser(prog="ddos_detector", description="Passive network monitoring foundation")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--interface", default=None, help="Interface to monitor")

    subparsers = parser.add_subparsers(dest="command")

    monitor = subparsers.add_parser("monitor", help="Run passive monitor mode", description="Run passive monitor mode")
    monitor.add_argument("--config", default="config/config.yaml")
    monitor.add_argument("--interface", default=None)

    detect_cmd = subparsers.add_parser("detect", help="Analyze traffic against a learned baseline", description="Analyze current traffic for DDoS-like anomalies")
    detect_cmd.add_argument("--config", default="config/config.yaml")
    detect_cmd.add_argument("--interface", default=None)
    detect_cmd.add_argument("--demo", action="store_true", help="Use a built-in demo window for demonstration")

    simulate_cmd = subparsers.add_parser("simulate", help="Generate a safe local simulation window", description="Generate a local-only simulation window for testing")
    simulate_cmd.add_argument("--config", default="config/config.yaml")
    simulate_cmd.add_argument("--mode", choices=["normal", "distributed"], default="normal")
    simulate_cmd.add_argument("--target", default="127.0.0.1")
    simulate_cmd.add_argument("--rate-limit", type=int, default=500)
    simulate_cmd.add_argument("--packet-limit", type=int, default=20000)
    simulate_cmd.add_argument("--max-sources", type=int, default=20)

    alert_cmd = subparsers.add_parser("alert", help="Create a structured alert record", description="Emit a safe, structured alert for suspicious or high-risk traffic")
    alert_cmd.add_argument("--config", default="config/config.yaml")
    alert_cmd.add_argument("--classification", choices=["NORMAL", "SUSPICIOUS", "HIGH_RISK"], default="SUSPICIOUS")
    alert_cmd.add_argument("--score", type=float, default=0.78)
    alert_cmd.add_argument("--reason", nargs="+", default=["Distributed traffic anomaly observed"])

    mitigate_cmd = subparsers.add_parser("mitigate", help="Apply a dry-run or configured mitigation rule", description="Create a temporary mitigation action without changing the host unless configured")
    mitigate_cmd.add_argument("--config", default="config/config.yaml")
    mitigate_cmd.add_argument("--target", default="127.0.0.1")
    mitigate_cmd.add_argument("--interface", default="lo")
    mitigate_cmd.add_argument("--reason", default="Dry-run mitigation for suspicious traffic")

    cleanup_cmd = subparsers.add_parser("cleanup", help="Clean up expired or all tracked mitigation rules", description="Remove temporary mitigation tracking data")
    cleanup_cmd.add_argument("--config", default="config/config.yaml")
    cleanup_cmd.add_argument("--all", action="store_true", help="Remove all tracked rules instead of expired ones only")

    return parser


def _demo_window() -> WindowMetric:
    return WindowMetric(
        window_seconds=5,
        packets=24000,
        bytes=6000000,
        packets_per_sec=4800,
        bytes_per_sec=1200000,
        tcp_packets=18000,
        udp_packets=4000,
        icmp_packets=200,
        syn_packets=2100,
        connection_attempts=1800,
        unique_src_ips=137,
        unique_dst_ips=10,
        dst_port_distribution={80: 2000, 443: 1500},
        avg_packet_size=250,
        burst_intensity=9.2,
        dest_concentration=0.62,
        raw=None,
    )


def _normal_window() -> WindowMetric:
    return WindowMetric(
        window_seconds=5,
        packets=760,
        bytes=470000,
        packets_per_sec=152,
        bytes_per_sec=94000,
        tcp_packets=550,
        udp_packets=180,
        icmp_packets=30,
        syn_packets=11,
        connection_attempts=13,
        unique_src_ips=8,
        unique_dst_ips=3,
        dst_port_distribution={80: 80, 443: 70},
        avg_packet_size=180,
        burst_intensity=1.1,
        dest_concentration=0.21,
        raw=None,
    )


def _format_result(result, score, classification):
    lines = []
    lines.append("TRAFFIC ANALYSIS")
    for indicator in result.indicators:
        status = "ANOMALY" if indicator.triggered else "NORMAL"
        lines.append(f"{indicator.name}: Current={indicator.current:.2f}, Baseline={indicator.baseline:.2f}, Deviation={indicator.deviation:.2f}x, Status={status}")
    lines.append(f"ANOMALY SCORE: {score:.2f}")
    lines.append(f"CLASSIFICATION: {classification}")
    lines.append(f"INDICATORS: {', '.join(result.triggered_indicators) if result.triggered_indicators else 'None'}")
    lines.append(f"REASON: {result.reason}")
    return "\n".join(lines)


def _cleanup_expired_rules(manager):
    removed = manager.cleanup_expired()
    cleanup_error = getattr(manager, "last_cleanup_error", None)
    if cleanup_error:
        logger.error(
            "Mitigation cleanup failed: %s",
            cleanup_error.get("message", cleanup_error),
        )
    return removed


def _run_simulate(args, cfg):
    sim_cfg = validate_simulation_config({
        "enabled": cfg.simulation.get("enabled", True),
        "mode": getattr(args, "mode", cfg.simulation.get("mode", "normal")),
        "target": getattr(args, "target", cfg.simulation.get("target", "127.0.0.1")),
        "rate_limit": getattr(args, "rate_limit", cfg.simulation.get("rate_limit", 500)),
        "packet_limit": getattr(args, "packet_limit", cfg.simulation.get("packet_limit", 20000)),
        "max_sources": getattr(args, "max_sources", cfg.simulation.get("max_sources", 20)),
    })
    window = simulate_window(sim_cfg.mode, sim_cfg)
    print(
        f"Simulation mode={sim_cfg.mode} target={sim_cfg.target} packets={window.packets} "
        f"packets_per_sec={window.packets_per_sec:.1f} unique_src_ips={window.unique_src_ips}"
    )
    return 0


def _run_alert(args, cfg):
    alert = maybe_emit_alert(
        args.classification,
        float(args.score),
        list(args.reason),
        current_metrics={"packets_per_sec": 1200, "unique_src_ips": 42},
        baseline={"packets_per_sec": 180, "unique_src_ips": 9},
        alert_cfg=getattr(cfg, "alerts", None) or cfg.alerts,
    )
    if alert is None:
        print(json.dumps({"classification": args.classification, "score": float(args.score), "emitted": False}, sort_keys=True))
        return 0
    print(json.dumps(alert, sort_keys=True))
    return 0


def _run_monitor(args, cfg, capture_factory=None):
    if capture_factory is None:
        capture_factory = open_capture
    if platform.system() != "Linux":
        print("Live monitoring requires Linux/WSL2. Windows is not supported for packet capture.", file=sys.stderr)
        return 2

    interface = getattr(args, "interface", None) or cfg.interface
    if not interface:
        print("No interface was provided and no default interface is configured.", file=sys.stderr)
        return 2
    if not os.path.isdir(f"/sys/class/net/{interface}"):
        print(f"Interface '{interface}' does not exist on this Linux host.", file=sys.stderr)
        return 2

    mitigation_manager = None
    try:
        with _monitor_instance_lock(interface):
            baseline_engine = BaselineEngine(
                history_windows=int(cfg.baseline.get("history_windows", 60)),
                minimum_samples=int(cfg.baseline.get("minimum_samples", 10)),
            )
            started_at = time.monotonic()
            windows = SlidingWindowAggregator(
                window_seconds=cfg.window_seconds,
                slide_seconds=getattr(cfg, "slide_seconds", cfg.window_seconds),
                started_at=started_at,
            )
            pending_windows = deque()
            high_risk_streak = 0
            mitigation_cfg = getattr(cfg, "mitigation", {}) or {}
            mitigation_manager = MitigationManager(mitigation_cfg) if mitigation_cfg.get("enabled") else None
            if mitigation_manager is not None:
                _cleanup_expired_rules(mitigation_manager)
            next_cleanup_at = started_at + MITIGATION_CLEANUP_INTERVAL_SECONDS
            print(f"Monitoring interface {interface} using passive capture. Press Ctrl+C to stop.")
            with capture_factory(interface, cfg.capture.get("bpf_filter", "")) as capture:
                while True:
                    now = time.monotonic()
                    if mitigation_manager is not None and now >= next_cleanup_at:
                        _cleanup_expired_rules(mitigation_manager)
                        next_cleanup_at = now + MITIGATION_CLEANUP_INTERVAL_SECONDS

                    timeout = min(
                        windows.seconds_until_next_window(now),
                        max(0.0, next_cleanup_at - now) if mitigation_manager is not None else float("inf"),
                    )
                    if not pending_windows:
                        wait_for_packets = getattr(capture, "wait_for_packets", None)
                        if callable(wait_for_packets):
                            wait_for_packets(timeout)
                        elif timeout > 0:
                            time.sleep(min(timeout, 0.05))

                    read_timed_packets = getattr(capture, "read_timed_packets", None)
                    if callable(read_timed_packets):
                        timed_batch = read_timed_packets(count=100)
                    else:
                        timed_batch = [
                            (time.monotonic(), packet)
                            for packet in capture.read_packets(count=100)
                        ]
                    now = time.monotonic()
                    for received_at, packet in timed_batch:
                        try:
                            record = extract_features(packet)
                        except (TypeError, ValueError):
                            logger.debug("Skipping malformed captured packet", exc_info=True)
                            continue
                        windows.add_packet(record, received_at)

                    pending_windows.extend(windows.pop_ready(now))
                    if not pending_windows:
                        continue

                    window_metric = pending_windows.popleft()

                    if not baseline_engine.is_ready():
                        baseline_engine.observe_bootstrap(window_metric)
                        print(
                            "LIVE WINDOW "
                            f"packet-rate: {window_metric.packets_per_sec:.1f} pps "
                            f"byte-rate: {window_metric.bytes_per_sec/1024:.1f} KB/s "
                            f"SYN-rate: {window_metric.syn_packets / max(1, window_metric.window_seconds):.1f}/s "
                            f"connection-rate: {window_metric.connection_attempts / max(1, window_metric.window_seconds):.1f}/s "
                            f"distributed-source: {window_metric.unique_src_ips} "
                            f"classification: BASELINE_WARMUP"
                        )
                        continue

                    detection = analyze_window(
                        window_metric,
                        baseline_engine,
                        minimum_indicators=int(cfg.detection.get("minimum_indicators", 2)),
                    )
                    score, classification = score_and_classify(
                        detection.indicators,
                        weights=cfg.scoring.get("weights", cfg.weights),
                        thresholds=cfg.scoring.get("thresholds", cfg.thresholds),
                    )
                    configured_consecutive = int(cfg.detection.get("minimum_consecutive_windows", 1))
                    if classification == "HIGH_RISK":
                        high_risk_streak += 1
                        if high_risk_streak < configured_consecutive:
                            classification = "SUSPICIOUS"
                    else:
                        high_risk_streak = 0
                    detection.score = float(score)
                    detection.classification = classification

                    if classification == "NORMAL":
                        baseline_engine.update(window_metric, is_anomalous=False)
                        mark_normal_window(interface, int(cfg.detection.get("recovery_windows", 2)))
                    else:
                        baseline_engine.update(window_metric, is_anomalous=True)

                    print(
                        "LIVE WINDOW "
                        f"packet-rate: {window_metric.packets_per_sec:.1f} pps "
                        f"byte-rate: {window_metric.bytes_per_sec/1024:.1f} KB/s "
                        f"SYN-rate: {window_metric.syn_packets / max(1, window_metric.window_seconds):.1f}/s "
                        f"connection-rate: {window_metric.connection_attempts / max(1, window_metric.window_seconds):.1f}/s "
                        f"distributed-source: {window_metric.unique_src_ips} "
                        f"destination-concentration: {window_metric.dest_concentration:.3f} "
                        f"score: {score:.2f} "
                        f"classification: {classification}"
                    )
                    if classification in {"SUSPICIOUS", "HIGH_RISK"}:
                        reasons = detection.triggered_indicators or [detection.reason]
                        baseline_snapshot = baseline_engine.snapshot()
                        raw_packets = window_metric.raw or []
                        source_ips = sorted({packet.src_ip for packet in raw_packets if packet.src_ip})
                        target_ips = sorted({packet.dst_ip for packet in raw_packets if packet.dst_ip})
                        target_ports = sorted({packet.dst_port for packet in raw_packets if packet.dst_port is not None})
                        mitigation_cfg = cfg.mitigation if isinstance(cfg.mitigation, dict) else {}
                        mitigation_outcomes = []
                        alert_context = {
                            "interface": interface,
                            "source_ips": source_ips,
                            "target_ips": target_ips,
                            "target_ports": target_ports,
                            "mitigation": {
                                "enabled": bool(mitigation_cfg.get("enabled", False)),
                                "auto_block_sources": bool(mitigation_cfg.get("auto_block_sources", False)),
                                "mechanism": mitigation_cfg.get("mechanism", "nftables"),
                                "max_auto_block_sources": mitigation_cfg.get("max_auto_block_sources", 5),
                                "rule_ttl_seconds": mitigation_cfg.get("rule_ttl_seconds", 60),
                                "decision": "Detected but not automatically blocked",
                                "reason": "Automatic mitigation is only allowed for explicitly attributable sources.",
                                "shared_nat_ambiguous": True,
                                "outcomes": mitigation_outcomes,
                            },
                        }
                        alert_kwargs = {
                            "classification": classification,
                            "score": float(score),
                            "reasons": reasons,
                            "current_metrics": {
                                "packets_per_sec": window_metric.packets_per_sec,
                                "bytes_per_sec": window_metric.bytes_per_sec,
                                "syn_rate": window_metric.syn_packets / max(1, window_metric.window_seconds),
                                "connection_rate": window_metric.connection_attempts / max(1, window_metric.window_seconds),
                                "unique_src_ips": window_metric.unique_src_ips,
                                "dest_concentration": window_metric.dest_concentration,
                                "avg_packet_size": window_metric.avg_packet_size,
                                "burst_intensity": window_metric.burst_intensity,
                                "source_distribution": source_ips,
                            },
                            "baseline": {
                                "packets_per_sec": baseline_snapshot.mean.get("packets_per_sec", 0.0),
                                "bytes_per_sec": baseline_snapshot.mean.get("bytes_per_sec", 0.0),
                                "syn_rate": baseline_snapshot.mean.get("syn_packets", 0.0) / max(1, window_metric.window_seconds),
                                "connection_rate": baseline_snapshot.mean.get("connection_attempts", 0.0) / max(1, window_metric.window_seconds),
                                "unique_src_ips": baseline_snapshot.mean.get("unique_src_ips", 0.0),
                            },
                            "alert_cfg": getattr(cfg, "alerts", None) or cfg.alerts,
                            "context": alert_context,
                        }

                        # Optionally auto-block top source IPs for HIGH_RISK when configured
                        mitigation_settings = getattr(cfg, "mitigation", {}) or {}
                        if isinstance(mitigation_settings, dict):
                            auto_block = mitigation_settings.get("auto_block_sources", False)
                        else:
                            auto_block = getattr(mitigation_settings, "auto_block_sources", False)
                        if classification == "HIGH_RISK" and auto_block:
                            # Only perform mitigation when mitigation is enabled in config
                            mitig_cfg = cfg.mitigation if isinstance(cfg.mitigation, dict) else getattr(cfg, "mitigation", {})
                            if mitig_cfg.get("enabled"):
                                manager = mitigation_manager
                                if manager is None:
                                    mitigation_outcomes.append({
                                        "decision": "Detected but not automatically blocked",
                                        "reason": "Mitigation manager is unavailable; no rule was created.",
                                        "shared_nat_ambiguous": True,
                                    })
                                else:
                                # select top source IPs from raw packet records
                                    srcs = [p.src_ip for p in (window_metric.raw or []) if getattr(p, 'src_ip', None)]
                                    from collections import Counter
                                    counts = Counter(srcs)
                                    limit = int(mitig_cfg.get("max_auto_block_sources", 5))
                                    blocked_this_window = 0
                                    for src, _ in counts.most_common():
                                        if blocked_this_window >= limit:
                                            break
                                        try:
                                            attribution = manager.assess_source_attribution(src)
                                            if not attribution["attributable"]:
                                                mitigation_outcomes.append({
                                                    "source": src,
                                                    "decision": "Detected but not automatically blocked",
                                                    "reason": attribution["reason"],
                                                    "shared_nat_ambiguous": attribution["shared_or_nat"],
                                                })
                                                continue
                                            destinations = Counter(
                                                p.dst_ip for p in (window_metric.raw or [])
                                                if getattr(p, "src_ip", None) == src and getattr(p, "dst_ip", None)
                                            )
                                            target = destinations.most_common(1)[0][0] if destinations else None
                                            if not target:
                                                continue
                                            result = manager.apply_source(
                                                src,
                                                target,
                                                interface,
                                                "auto-block from monitor HIGH_RISK",
                                                classification=classification,
                                                score=float(score),
                                            )
                                            mitigation_outcomes.append({
                                                "source": src,
                                                "decision": "Detected and temporarily blocked" if result.get("success") else "Detected but not automatically blocked",
                                                "reason": result.get("message", result.get("error", "Mitigation was not applied.")),
                                                "shared_nat_ambiguous": False,
                                                "result": result,
                                            })
                                            if result.get("success"):
                                                blocked_this_window += 1
                                            print(f"Mitigation: {result.get('message')}")
                                        except Exception as exc:
                                            mitigation_outcomes.append({
                                                "source": src,
                                                "decision": "Detected but not automatically blocked",
                                                "reason": f"Mitigation failed safely: {exc}",
                                                "shared_nat_ambiguous": False,
                                            })
                                            print(f"Mitigation failed for {src}: {exc}")
                        if mitigation_outcomes:
                            applied = [item for item in mitigation_outcomes if item["decision"] == "Detected and temporarily blocked"]
                            alert_context["mitigation"]["decision"] = (
                                "Detected and temporarily blocked" if applied else "Detected but not automatically blocked"
                            )
                            alert_context["mitigation"]["reason"] = "; ".join(
                                sorted({item["reason"] for item in mitigation_outcomes})
                            )
                            alert_context["mitigation"]["shared_nat_ambiguous"] = any(
                                item["shared_nat_ambiguous"] for item in mitigation_outcomes
                            )
                            alert_context["mitigation"]["applied_rules"] = [
                                item["result"].get("rule_id")
                                for item in applied
                                if item.get("result", {}).get("rule_id")
                            ]
                        maybe_emit_alert(**alert_kwargs)

                    if classification in {"SUSPICIOUS", "HIGH_RISK"}:
                        print("Indicators:")
                        for indicator in detection.indicators:
                            if indicator.triggered:
                                print(f"- {indicator.name}: deviation={indicator.deviation:.2f}x")

    except KeyboardInterrupt:
        print("\nStopping live monitor.")
        if mitigation_manager is not None:
            try:
                _cleanup_expired_rules(mitigation_manager)
            except Exception as exc:
                print(f"Expired-rule cleanup failed during shutdown: {exc}", file=sys.stderr)
                return 1
            cleanup_error = getattr(mitigation_manager, "last_cleanup_error", None)
            if cleanup_error:
                print(
                    "Expired-rule cleanup failed during shutdown: "
                    f"{cleanup_error.get('message', 'unknown cleanup error')}",
                    file=sys.stderr,
                )
                return 1
        return 0
    except OSError as exc:
        print(f"Live monitoring failed: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive fallback
        print(f"Live monitoring error: {exc}", file=sys.stderr)
        return 1


def _run_mitigation(args, cfg):
    manager = MitigationManager(cfg.mitigation)
    result = manager.apply(args.target, args.interface, args.reason)
    print(result.get("message", "No mitigation action performed."))
    if result.get("rule"):
        print(result["rule"])
    return 0


def _run_cleanup(args, cfg):
    manager = MitigationManager(cfg.mitigation)
    if args.all:
        removed = manager.cleanup_all()
        print(f"Removed all tracked mitigation rules: {removed}")
    else:
        removed = manager.cleanup_expired()
        print(f"Removed expired mitigation rules: {removed}")
    if manager.last_cleanup_error:
        print(
            f"Mitigation cleanup failed: {manager.last_cleanup_error.get('message', 'unknown cleanup error')}",
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        cfg = load_config(args.config if hasattr(args, "config") else "config/config.yaml")
        setup_logging(cfg.logging.get("level", "INFO"), cfg.logging.get("json", False))

        if args.command == "monitor":
            return _run_monitor(args, cfg)

        if args.command == "detect":
            baseline_engine = BaselineEngine(history_windows=int(cfg.baseline.get("history_windows", 60)), minimum_samples=int(cfg.baseline.get("minimum_samples", 10)))
            for _ in range(baseline_engine.minimum_samples):
                baseline_engine.update(_normal_window(), is_anomalous=False)
            current = _demo_window() if getattr(args, "demo", False) else _normal_window()
            detection = analyze_window(current, baseline_engine, minimum_indicators=int(cfg.detection.get("minimum_indicators", 2)))
            score, classification = score_and_classify(detection.indicators, weights=cfg.scoring.get("weights", cfg.weights), thresholds=cfg.scoring.get("thresholds", cfg.thresholds))
            detection.score = float(score)
            detection.classification = classification
            detection.reason = detection.reason if detection.triggered_indicators else "No anomaly detected; observed traffic remains within learned baseline values."
            print(_format_result(detection, detection.score, detection.classification))
            return 0

        if args.command == "simulate":
            return _run_simulate(args, cfg)

        if args.command == "alert":
            return _run_alert(args, cfg)

        if args.command == "mitigate":
            return _run_mitigation(args, cfg)

        if args.command == "cleanup":
            return _run_cleanup(args, cfg)

        if args.command is None:
            parser.print_help()
            return 0

        parser.print_help()
        return 0
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Error: required file not found: {exc.filename}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Error: runtime I/O failure: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - defensive fallback for runtime failures
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
