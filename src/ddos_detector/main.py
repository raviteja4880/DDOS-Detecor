"""CLI entrypoint for the passive DDoS detector.

The project stays defensive by default: it can run simulations and dry-run
alerting/mitigation flows without altering the host system unless explicitly
enabled in configuration.
"""
import argparse
import json
import sys

from .alerts import maybe_emit_alert
from .baseline import BaselineEngine
from .config import load_config
from .detector import analyze_window
from .logging_config import setup_logging
from .mitigation import MitigationManager
from .models import WindowMetric
from .scoring import score_and_classify
from .simulator import simulate_window, validate_simulation_config


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
    )
    if alert is None:
        print(json.dumps({"classification": args.classification, "score": float(args.score), "emitted": False}, sort_keys=True))
        return 0
    print(json.dumps(alert, sort_keys=True))
    return 0


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
    return 0


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        cfg = load_config(args.config if hasattr(args, "config") else "config/config.yaml")
        setup_logging(cfg.logging.get("level", "INFO"), cfg.logging.get("json", False))

        if args.command == "monitor":
            print("Passive monitor mode ready. Phase 1 foundation only.")
            return 0

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
