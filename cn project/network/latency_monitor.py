"""
Active Latency and Jitter Monitor.
Executes ICMP ping measurements on Windows, tracking round-trip time, jitter, and packet loss.
"""
import re
import subprocess
import threading
from collections import deque
from typing import Optional, Dict, Any
import logging

import config

logger = logging.getLogger(__name__)

# Regular expressions for parsing Windows ping output
PING_TIME_REGEX = re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
PING_LOSS_REGEX = re.compile(r"\((\d+)%\s*loss\)", re.IGNORECASE)


class LatencyMonitor:
    """
    Monitors round-trip latency, jitter, and packet loss via system ping.
    Maintains a rolling history of recent attempts in a thread-safe manner.
    """

    def __init__(self, target: str = config.DEFAULT_PING_TARGET, window_size: int = config.PING_WINDOW_SIZE):
        self.target = target
        self.window_size = window_size
        self.timeout_ms = config.PING_TIMEOUT_MS
        
        self._lock = threading.Lock()
        self._recent_attempts = deque(maxlen=window_size)  # Stores True (success) / False (fail)
        self._recent_latencies = deque(maxlen=window_size) # Stores float ms for successful pings
        self._last_latency: Optional[float] = None
        self._last_jitter: Optional[float] = None
        self._last_status: str = "Uninitialized"

    def set_target(self, target: str):
        """Update ping target IP or hostname."""
        with self._lock:
            self.target = target
            self._recent_attempts.clear()
            self._recent_latencies.clear()
            self._last_latency = None
            self._last_jitter = None

    def probe(self) -> Dict[str, Any]:
        """
        Executes a single ICMP ping to the target.
        Thread-safe and handles Windows command quirks and errors gracefully.
        Returns:
            Dict containing latency_ms, jitter_ms, packet_loss_pct, status
        """
        cmd = ["ping", "-n", "1", "-w", str(self.timeout_ms), self.target]
        success = False
        latency: Optional[float] = None
        status = "Failed"

        try:
            # Execute ping process
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=(self.timeout_ms / 1000.0) + 1.0,
                check=False
            )
            stdout = res.stdout or ""

            match = PING_TIME_REGEX.search(stdout)
            if match and "Reply from" in stdout:
                raw_time = match.group(1)
                latency = max(0.1, float(raw_time))
                success = True
                status = "Success"
            elif "Request timed out" in stdout:
                status = "Timeout"
            elif "Destination host unreachable" in stdout:
                status = "Unreachable"
            elif "General failure" in stdout:
                status = "General failure (No driver / sandbox restricted)"
            else:
                status = "No reply"

        except subprocess.TimeoutExpired:
            status = "Command timeout"
        except Exception as e:
            status = f"Execution error: {type(e).__name__}"

        # Update metrics in thread-safe block
        with self._lock:
            self._recent_attempts.append(success)
            self._last_status = status

            if success and latency is not None:
                # Compute jitter relative to the previous successful latency
                if self._last_latency is not None:
                    self._last_jitter = abs(latency - self._last_latency)
                else:
                    self._last_jitter = 0.0

                self._last_latency = latency
                self._recent_latencies.append(latency)
            else:
                self._last_latency = None
                # Retain previous jitter or mark None if disconnected
                if len(self._recent_latencies) == 0:
                    self._last_jitter = None

            # Calculate rolling packet loss %
            total_attempts = len(self._recent_attempts)
            if total_attempts > 0:
                failed_attempts = self._recent_attempts.count(False)
                loss_pct = round((failed_attempts / total_attempts) * 100.0, 1)
            else:
                loss_pct = None

            return {
                "latency_ms": round(self._last_latency, 2) if self._last_latency is not None else None,
                "jitter_ms": round(self._last_jitter, 2) if self._last_jitter is not None else None,
                "packet_loss_pct": loss_pct,
                "status": self._last_status,
                "target": self.target
            }

    def get_latest_metrics(self) -> Dict[str, Any]:
        """Return the current cached latency state without blocking."""
        with self._lock:
            total_attempts = len(self._recent_attempts)
            loss_pct = None
            if total_attempts > 0:
                loss_pct = round((self._recent_attempts.count(False) / total_attempts) * 100.0, 1)

            return {
                "latency_ms": round(self._last_latency, 2) if self._last_latency is not None else None,
                "jitter_ms": round(self._last_jitter, 2) if self._last_jitter is not None else None,
                "packet_loss_pct": loss_pct,
                "status": self._last_status,
                "target": self.target
            }
