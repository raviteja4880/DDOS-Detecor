"""AI Studio headless CLI entry point for Distributed DDoS Detection Using Network Traffic Analysis.

Runs safe, non-networked demonstration commands from src/ddos_detector/main.py
and prints the verification status to the terminal view without modifying any
host firewall rules or transmitting network packets.
"""

from __future__ import annotations

import pathlib
import platform
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from ddos_detector.main import main as cli_main


def main() -> None:
    print("=" * 76)
    print("DISTRIBUTED DDOS DETECTION USING NETWORK TRAFFIC ANALYSIS — CLI RUNNER")
    print("=" * 76)
    print(f"Python Version : {sys.version.split()[0]}")
    print(f"Platform       : {platform.platform()}")
    print(f"iproute2 (ip)  : {shutil.which('ip') or 'NOT FOUND'}")
    print(f"nftables (nft) : {shutil.which('nft') or 'NOT FOUND'}")
    print("-" * 76)

    print("\n[1] Safe Demo Detection (python -m ddos_detector detect --demo)")
    print("-" * 76)
    cli_main(["detect", "--demo"])

    print("\n[2] Safe Normal Traffic Simulation (python -m ddos_detector simulate --mode normal --target 127.0.0.1)")
    print("-" * 76)
    cli_main(["simulate", "--mode", "normal", "--target", "127.0.0.1"])

    print("\n[3] Safe Distributed Traffic Simulation (python -m ddos_detector simulate --mode distributed --target 10.0.0.5)")
    print("-" * 76)
    cli_main(["simulate", "--mode", "distributed", "--target", "10.0.0.5"])
    print("=" * 76)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
