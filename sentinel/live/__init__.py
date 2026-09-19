"""Live capture (Linux), feeding the same pipeline as a pcap file."""

from sentinel.live.capture import Capture, LiveError, open_capture

__all__ = ["Capture", "LiveError", "open_capture"]
