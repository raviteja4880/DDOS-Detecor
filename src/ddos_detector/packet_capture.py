"""Packet capture scaffold. Real capture (Scapy/tcpdump) will be implemented later.

Phase 1 unit tests do not require live capture; this module provides safe placeholders.
"""


def open_capture(interface: str, bpf_filter: str = ""):
    """Return a context manager-like object that yields packets. Placeholder for Phase 1."""

    class DummyCapture:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read_packets(self, count: int = 100):
            return []

    return DummyCapture()
