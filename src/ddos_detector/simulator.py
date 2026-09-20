from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Dict, List

from .models import WindowMetric

SAFE_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "172.")


@dataclass
class SimulationConfig:
    enabled: bool = True
    mode: str = "normal"
    target: str = "127.0.0.1"
    rate_limit: int = 500
    packet_limit: int = 20000
    max_sources: int = 20

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("simulation.enabled must be boolean")
        if self.mode not in {"normal", "distributed"}:
            raise ValueError("simulation.mode must be 'normal' or 'distributed'")
        if not self.target:
            raise ValueError("simulation.target is required")
        if not self._is_safe_target(self.target):
            raise ValueError("simulation.target must be localhost or a private/lab address")
        if self.rate_limit <= 0 or self.rate_limit > 20000:
            raise ValueError("simulation.rate_limit must be between 1 and 20000")
        if self.packet_limit <= 0 or self.packet_limit > 500000:
            raise ValueError("simulation.packet_limit must be between 1 and 500000")
        if self.max_sources <= 0 or self.max_sources > 500:
            raise ValueError("simulation.max_sources must be between 1 and 500")

    @staticmethod
    def _is_safe_target(target: str) -> bool:
        target = str(target).strip()
        if target in {"localhost", "127.0.0.1", "::1"}:
            return True
        try:
            addr = ip_address(target)
        except ValueError:
            return False
        if addr.version == 6:
            return str(addr) in {"::1"}
        if addr.is_private:
            return True
        return target.startswith("127.")


def validate_simulation_config(cfg: Dict[str, object] | None) -> SimulationConfig:
    if cfg is None:
        cfg = {"enabled": True, "mode": "normal", "target": "127.0.0.1", "rate_limit": 500, "packet_limit": 20000, "max_sources": 20}
    sim_cfg = SimulationConfig(
        enabled=bool(cfg.get("enabled", True)),
        mode=str(cfg.get("mode", "normal")),
        target=str(cfg.get("target", "127.0.0.1")),
        rate_limit=int(cfg.get("rate_limit", 500)),
        packet_limit=int(cfg.get("packet_limit", 20000)),
        max_sources=int(cfg.get("max_sources", 20)),
    )
    sim_cfg.validate()
    return sim_cfg


def make_normal_window(cfg: Dict[str, object] | SimulationConfig | None = None) -> WindowMetric:
    sim_cfg = cfg if isinstance(cfg, SimulationConfig) else validate_simulation_config(cfg)
    rate = min(int(sim_cfg.rate_limit), 300)
    return WindowMetric(
        window_seconds=5,
        packets=rate,
        bytes=rate * 160,
        packets_per_sec=float(rate),
        bytes_per_sec=float(rate * 160),
        tcp_packets=int(rate * 0.7),
        udp_packets=int(rate * 0.25),
        icmp_packets=int(rate * 0.05),
        syn_packets=8,
        connection_attempts=10,
        unique_src_ips=6,
        unique_dst_ips=2,
        dst_port_distribution={80: 50, 443: 40},
        avg_packet_size=160,
        burst_intensity=1.1,
        dest_concentration=0.22,
        raw=None,
    )


def make_distributed_window(cfg: Dict[str, object] | SimulationConfig | None = None) -> WindowMetric:
    sim_cfg = cfg if isinstance(cfg, SimulationConfig) else validate_simulation_config(cfg)
    rate = min(int(sim_cfg.rate_limit), 4000)
    unique_sources = min(max(20, sim_cfg.max_sources), 150)
    return WindowMetric(
        window_seconds=5,
        packets=int(rate),
        bytes=int(rate * 250),
        packets_per_sec=float(rate),
        bytes_per_sec=float(rate * 250),
        tcp_packets=int(rate * 0.8),
        udp_packets=int(rate * 0.15),
        icmp_packets=int(rate * 0.05),
        syn_packets=max(100, int(rate * 0.45)),
        connection_attempts=max(100, int(rate * 0.4)),
        unique_src_ips=unique_sources,
        unique_dst_ips=4,
        dst_port_distribution={80: 250, 443: 180},
        avg_packet_size=250,
        burst_intensity=7.8,
        dest_concentration=0.62,
        raw=None,
    )


def simulate_window(mode: str = "normal", cfg: Dict[str, object] | SimulationConfig | None = None) -> WindowMetric:
    if mode == "distributed":
        return make_distributed_window(cfg)
    if mode == "normal":
        return make_normal_window(cfg)
    raise ValueError("mode must be 'normal' or 'distributed'")
