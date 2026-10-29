"""Passive packet capture for Linux/WSL2 using Scapy.

This module intentionally avoids shelling out to tcpdump and instead uses Scapy's
capture APIs directly through a lightweight, non-storing capture queue.

The capture implementation is provided as a context manager with a small
read_packets(count:int)->List[Packet] API that the live monitor expects. This
file implements a capture backed by Scapy's AsyncSniffer (preferred) while
maintaining backward-compatible behavior.
"""

from __future__ import annotations

import os
import platform
import logging
import threading
import time
from collections import deque
from typing import Any, Deque, List

from scapy.all import AsyncSniffer

logger = logging.getLogger(__name__)


class ScapyAsyncCapture:
    """Context manager that captures packets using Scapy.AsyncSniffer.

    Provides:
      - __enter__/__exit__ for use in `with open_capture(...) as capture:`
      - read_packets(count) -> List[Packet]
      - stop() to request graceful shutdown

    The implementation does not store packets in Scapy (store=False) and
    appends incoming packets into a bounded in-memory deque that is drained by
    the monitor loop. This avoids unbounded memory growth.
    """

    def __init__(self, interface: str, bpf_filter: str = "", queue_max: int = 10000):
        self.interface = interface
        self.bpf_filter = bpf_filter or ""
        self._queue: Deque[tuple[float, Any]] = deque()
        self._condition = threading.Condition()
        self._sniffer: AsyncSniffer | None = None
        self._stopped = False
        self._queue_max = max(1, int(queue_max))

    def _on_packet(self, packet: Any) -> None:
        # Drop packets if queue grows too large to avoid memory blowups
        if packet is None:
            return
        with self._condition:
            if len(self._queue) >= self._queue_max:
                self._queue.popleft()
            self._queue.append((time.monotonic(), packet))
            self._condition.notify()

    def wait_for_packets(self, timeout: float | None = None) -> bool:
        """Block until a packet is queued, capture stops, or timeout expires."""
        with self._condition:
            return self._condition.wait_for(
                lambda: bool(self._queue) or self._stopped,
                timeout=max(0.0, timeout) if timeout is not None else None,
            ) and bool(self._queue)

    def __enter__(self):
        if os.name == "nt" or platform.system() != "Linux":
            raise OSError("Live packet capture requires Linux/WSL2.")
        self._stopped = False
        # AsyncSniffer runs in a background thread and can be started/stopped.
        self._sniffer = AsyncSniffer(iface=self.interface, filter=self.bpf_filter, prn=self._on_packet, store=False)
        self._sniffer.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        # Ensure the sniffer is stopped on context exit
        self.stop()
        return False

    def stop(self) -> None:
        with self._condition:
            if self._stopped:
                return
            self._stopped = True
            self._condition.notify_all()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                logger.exception("Failed to stop Scapy packet capture cleanly")

    def read_packets(self, count: int = 100) -> List[Any]:
        return [packet for _, packet in self.read_timed_packets(count)]

    def read_timed_packets(self, count: int = 100) -> List[tuple[float, Any]]:
        """Drain captured packets together with their monotonic capture times."""
        packets: List[Any] = []
        with self._condition:
            while len(packets) < max(1, int(count)) and self._queue:
                packets.append(self._queue.popleft())
        return packets


LinuxPacketCapture = ScapyAsyncCapture


def open_capture(interface: str, bpf_filter: str = ""):
    """Return a Linux capture session compatible with the live monitor pipeline.

    This returns a context manager that implements the minimal capture API used
    by the monitor. Keep the function signature stable for backward
    compatibility.
    """
    if not interface:
        raise ValueError("Network interface is required for live monitoring")
    if os.name == "nt" or platform.system() != "Linux":
        raise OSError("Live packet capture requires Linux/WSL2.")
    return ScapyAsyncCapture(interface=interface, bpf_filter=bpf_filter)
