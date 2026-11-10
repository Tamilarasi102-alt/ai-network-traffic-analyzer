"""
Traffic Feature Extraction and Metric Aggregation.
Combines psutil OS-level counters, Scapy packet metadata, and LatencyMonitor probing into a unified observation.
"""
import time
import math
import random
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import psutil

from network.interface_manager import InterfaceManager
from network.latency_monitor import LatencyMonitor
from network.packet_capture import PacketCaptureWorker

logger = logging.getLogger(__name__)


class TrafficFeatureCollector:
    """
    Coordinates data collection across psutil counters, Scapy packet inspection, and active latency probing.
    Computes accurate rate metrics using delta calculations over elapsed time.
    """

    def __init__(self, interface_name: str, ping_target: Optional[str] = None):
        self.interface_name = interface_name
        self.latency_monitor = LatencyMonitor(target=ping_target) if ping_target else LatencyMonitor()
        self.packet_worker = PacketCaptureWorker(interface_name=interface_name)

        # Baseline counters for delta calculation
        self._last_time: Optional[float] = None
        self._last_bytes_recv: int = 0
        self._last_bytes_sent: int = 0
        self._last_packets_recv: int = 0
        self._last_packets_sent: int = 0
        self._initialized = False

    def start(self):
        """Start underlying packet sniffer worker."""
        self._initialize_counters()
        self.packet_worker.start()

    def stop(self):
        """Stop packet sniffer worker."""
        self.packet_worker.stop()

    def _initialize_counters(self):
        """Record initial counter state so first measurement computes from an accurate delta."""
        counters = psutil.net_io_counters(pernic=True)
        if self.interface_name in counters:
            nic = counters[self.interface_name]
            self._last_bytes_recv = nic.bytes_recv
            self._last_bytes_sent = nic.bytes_sent
            self._last_packets_recv = nic.packets_recv
            self._last_packets_sent = nic.packets_sent
        self._last_time = time.time()
        self._initialized = True

    def collect_live_metrics(self) -> Dict[str, Any]:
        """
        Collect actual measured network statistics for the elapsed measurement window.
        Uses OS network counters for throughput and Scapy for protocol metadata.
        Never fabricates values in Live Mode.
        """
        now = time.time()
        if not self._initialized or self._last_time is None:
            self._initialize_counters()
            time.sleep(0.05)
            now = time.time()

        dt = max(0.1, now - self._last_time)
        self._last_time = now

        counters = psutil.net_io_counters(pernic=True)
        if self.interface_name not in counters:
            # Interface might have gone down or disappeared
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "interface_name": self.interface_name,
                "capture_mode": "live",
                "error": f"Interface '{self.interface_name}' not found in system counters.",
                "download_mbps": None,
                "upload_mbps": None,
                "packets_per_sec": None,
                "avg_packet_size": None,
                "bandwidth_util_percent": None,
                "latency_ms": None,
                "jitter_ms": None,
                "packet_loss_pct": None,
                "tcp_ratio": None,
                "udp_ratio": None,
                "icmp_ratio": None,
                "unique_flows": None,
                "is_live": True
            }

        nic = counters[self.interface_name]

        # Deltas
        bytes_recv_delta = nic.bytes_recv - self._last_bytes_recv
        bytes_sent_delta = nic.bytes_sent - self._last_bytes_sent
        pkts_recv_delta = nic.packets_recv - self._last_packets_recv
        pkts_sent_delta = nic.packets_sent - self._last_packets_sent

        # Handle counter rollover / restart
        if bytes_recv_delta < 0 or bytes_sent_delta < 0:
            bytes_recv_delta = 0
            bytes_sent_delta = 0
            pkts_recv_delta = 0
            pkts_sent_delta = 0

        # Update cached counter baselines
        self._last_bytes_recv = nic.bytes_recv
        self._last_bytes_sent = nic.bytes_sent
        self._last_packets_recv = nic.packets_recv
        self._last_packets_sent = nic.packets_sent

        # Throughput calculations (Bytes/sec -> bits/sec -> Mbps)
        bytes_recv_per_sec = bytes_recv_delta / dt
        bytes_sent_per_sec = bytes_sent_delta / dt
        download_mbps = round((bytes_recv_per_sec * 8.0) / 1_000_000.0, 3)
        upload_mbps = round((bytes_sent_per_sec * 8.0) / 1_000_000.0, 3)

        # Packet rates
        pkts_recv_per_sec = pkts_recv_delta / dt
        pkts_sent_per_sec = pkts_sent_delta / dt
        packets_per_sec = round(pkts_recv_per_sec + pkts_sent_per_sec, 1)

        # Average packet size
        total_delta_pkts = pkts_recv_delta + pkts_sent_delta
        total_delta_bytes = bytes_recv_delta + bytes_sent_delta
        avg_packet_size: Optional[float] = None
        if total_delta_pkts > 0:
            avg_packet_size = round(total_delta_bytes / total_delta_pkts, 1)

        # Bandwidth utilization (only when interface speed is known)
        iface_speed = InterfaceManager.get_interface_speed(self.interface_name)
        bandwidth_util_pct: Optional[float] = None
        if iface_speed and iface_speed > 0:
            total_mbps = download_mbps + upload_mbps
            util = (total_mbps / iface_speed) * 100.0
            bandwidth_util_pct = round(min(100.0, max(0.0, util)), 2)

        # Active latency probe
        ping_res = self.latency_monitor.probe()

        # Scapy packet metadata snapshot
        scapy_meta = self.packet_worker.snapshot_and_reset()

        # Merge Scapy metrics if available and captured; otherwise fallback cleanly
        if not scapy_meta["scapy_degraded"] and scapy_meta["scapy_packets"] > 0:
            tcp_ratio = scapy_meta["tcp_ratio"]
            udp_ratio = scapy_meta["udp_ratio"]
            icmp_ratio = scapy_meta["icmp_ratio"]
            other_ratio = scapy_meta["other_ratio"]
            unique_flows = scapy_meta["unique_flows"]
            if scapy_meta["avg_packet_size"] > 0:
                avg_packet_size = scapy_meta["avg_packet_size"]
        else:
            # Scapy not sniffing or restricted; provide None to indicate unmeasured
            tcp_ratio = None
            udp_ratio = None
            icmp_ratio = None
            other_ratio = None
            unique_flows = None

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface_name": self.interface_name,
            "capture_mode": "live",
            "is_live": True,
            "download_mbps": download_mbps,
            "upload_mbps": upload_mbps,
            "packets_per_sec": packets_per_sec,
            "packets_recv_per_sec": round(pkts_recv_per_sec, 1),
            "packets_sent_per_sec": round(pkts_sent_per_sec, 1),
            "bytes_recv_per_sec": round(bytes_recv_per_sec, 1),
            "bytes_sent_per_sec": round(bytes_sent_per_sec, 1),
            "avg_packet_size": avg_packet_size,
            "interface_speed_mbps": iface_speed,
            "bandwidth_util_percent": bandwidth_util_pct,
            "latency_ms": ping_res.get("latency_ms"),
            "jitter_ms": ping_res.get("jitter_ms"),
            "packet_loss_pct": ping_res.get("packet_loss_pct"),
            "ping_status": ping_res.get("status"),
            "ping_target": ping_res.get("target"),
            "tcp_ratio": tcp_ratio,
            "udp_ratio": udp_ratio,
            "icmp_ratio": icmp_ratio,
            "other_ratio": other_ratio,
            "unique_flows": unique_flows,
            "scapy_status": scapy_meta.get("scapy_status"),
            "scapy_degraded": scapy_meta.get("scapy_degraded"),
            "scapy_message": scapy_meta.get("scapy_message")
        }


def generate_demo_traffic(scenario: str = "normal", tick: int = 0) -> Dict[str, Any]:
    """
    Generates controlled simulated network traffic for Demo Mode.
    Explicitly marked as DEMO DATA — NOT LIVE NETWORK TRAFFIC.
    Supports scenarios: 'normal', 'medium', 'high'.
    """
    t = tick * 0.2
    noise = math.sin(t) * 0.15 + (random.random() - 0.5) * 0.1

    if scenario == "high":
        # Congested state: heavy traffic, high latency, queue buildup
        dl = max(40.0, 95.0 + math.sin(t * 0.8) * 35.0 + (random.random() * 15.0))
        ul = max(15.0, 38.0 + math.cos(t * 0.6) * 12.0 + (random.random() * 8.0))
        pps = max(2000.0, 4800.0 + math.sin(t * 0.5) * 1500.0 + (random.random() * 400.0))
        avg_pkt = 1150.0 + (random.random() - 0.5) * 180.0
        util = min(99.0, max(75.0, 88.0 + math.sin(t) * 8.0))
        lat = max(140.0, 220.0 + math.sin(t * 0.7) * 70.0 + (random.random() * 30.0))
        jitter = max(20.0, 45.0 + (random.random() * 35.0))
        loss = max(4.0, 12.5 + math.sin(t * 0.4) * 5.0 + (random.random() * 3.0))
        tcp = 0.55
        udp = 0.40
        icmp = 0.05
        flows = int(90 + (random.random() * 60))
    elif scenario == "medium":
        # Moderate state: streaming or active transfers
        dl = max(15.0, 42.0 + math.sin(t * 0.5) * 16.0 + (random.random() * 8.0))
        ul = max(4.0, 14.0 + math.cos(t * 0.4) * 5.0 + (random.random() * 3.0))
        pps = max(800.0, 1800.0 + math.sin(t * 0.6) * 500.0)
        avg_pkt = 850.0 + (random.random() - 0.5) * 120.0
        util = min(72.0, max(42.0, 56.0 + math.sin(t * 0.5) * 10.0))
        lat = max(45.0, 82.0 + math.sin(t * 0.5) * 25.0)
        jitter = max(5.0, 14.0 + (random.random() * 8.0))
        loss = max(0.5, 2.2 + (random.random() * 1.5))
        tcp = 0.72
        udp = 0.24
        icmp = 0.04
        flows = int(45 + (random.random() * 25))
    else:
        # Normal state (Low Congestion): healthy web/idle traffic
        dl = max(0.8, 6.5 + math.sin(t * 0.4) * 3.5 + (random.random() * 1.5))
        ul = max(0.2, 1.8 + math.cos(t * 0.3) * 0.9 + (random.random() * 0.5))
        pps = max(50.0, 240.0 + math.sin(t * 0.5) * 90.0)
        avg_pkt = 580.0 + (random.random() - 0.5) * 150.0
        util = min(25.0, max(2.0, 11.0 + math.sin(t * 0.3) * 4.0))
        lat = max(15.0, 28.0 + math.sin(t * 0.5) * 7.0)
        jitter = max(0.5, 2.4 + (random.random() * 1.8))
        loss = 0.0 if random.random() > 0.15 else 0.5
        tcp = 0.82
        udp = 0.15
        icmp = 0.03
        flows = int(12 + (random.random() * 8))

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "interface_name": "Demo Simulation Adapter",
        "capture_mode": "demo",
        "is_live": False,
        "scenario": scenario,
        "download_mbps": round(dl, 3),
        "upload_mbps": round(ul, 3),
        "packets_per_sec": round(pps, 1),
        "packets_recv_per_sec": round(pps * 0.7, 1),
        "packets_sent_per_sec": round(pps * 0.3, 1),
        "bytes_recv_per_sec": round((dl * 1_000_000) / 8.0, 1),
        "bytes_sent_per_sec": round((ul * 1_000_000) / 8.0, 1),
        "avg_packet_size": round(avg_pkt, 1),
        "interface_speed_mbps": 100.0,
        "bandwidth_util_percent": round(util, 2),
        "latency_ms": round(lat, 2),
        "jitter_ms": round(jitter, 2),
        "packet_loss_pct": round(loss, 1),
        "ping_status": "Simulated Success",
        "ping_target": "Demo Loopback (Virtual)",
        "tcp_ratio": round(tcp, 3),
        "udp_ratio": round(udp, 3),
        "icmp_ratio": round(icmp, 3),
        "other_ratio": round(max(0.0, 1.0 - (tcp + udp + icmp)), 3),
        "unique_flows": flows,
        "scapy_status": "Demo Simulated",
        "scapy_degraded": False,
        "scapy_message": "Running controlled demo network scenario."
    }
