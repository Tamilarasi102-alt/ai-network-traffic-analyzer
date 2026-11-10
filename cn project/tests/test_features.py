"""
Unit Tests for Network Feature Extraction, Rate Calculations, and Telemetry Logic.
"""
import pytest
from network.interface_manager import InterfaceManager
from network.latency_monitor import LatencyMonitor
from network.packet_capture import PacketCaptureWorker
from network.traffic_features import generate_demo_traffic
from ml.feature_schema import sanitize_feature_value, extract_features_from_dict, FEATURE_COLUMNS


def test_sanitize_feature_value():
    """Verify robust sanitization of missing, string, and invalid values."""
    assert sanitize_feature_value("download_mbps", 42.5) == 42.5
    assert sanitize_feature_value("download_mbps", "12.3") == 12.3
    assert sanitize_feature_value("download_mbps", "N/A") == 0.0
    assert sanitize_feature_value("download_mbps", "Unavailable") == 0.0
    assert sanitize_feature_value("download_mbps", None) == 0.0
    assert sanitize_feature_value("download_mbps", float("nan")) == 0.0
    assert sanitize_feature_value("download_mbps", -5.0) == 0.0
    # Imputation defaults
    assert sanitize_feature_value("avg_packet_size", None) == 512.0
    assert sanitize_feature_value("latency_ms", None) == 25.0


def test_extract_features_from_dict():
    """Ensure extracted feature vectors adhere to canonical columns and order."""
    raw = {
        "download_mbps": 15.2,
        "upload_mbps": 3.1,
        "packets_per_sec": 450,
        "avg_packet_size": "N/A",  # Should be imputed
        "bandwidth_util_percent": None,
        "latency_ms": 32.0,
        "jitter_ms": 2.1,
        "packet_loss_pct": 0.0,
        "tcp_ratio": 0.85,
        "udp_ratio": 0.12,
        "icmp_ratio": 0.03,
        "unique_flows": 18
    }

    df = extract_features_from_dict(raw)
    assert list(df.columns) == FEATURE_COLUMNS
    assert len(df) == 1
    assert df.loc[0, "download_mbps"] == 15.2
    assert df.loc[0, "avg_packet_size"] == 512.0  # Imputed default
    assert df.loc[0, "bandwidth_util_percent"] == 0.0


def test_interface_discovery():
    """Verify that interface discovery returns a list of dictionaries with expected keys."""
    ifaces = InterfaceManager.get_interfaces()
    assert isinstance(ifaces, list)
    if len(ifaces) > 0:
        iface = ifaces[0]
        assert "name" in iface
        assert "is_up" in iface
        assert "is_recommended" in iface
        assert "display_name" in iface
        assert "adapter_type" in iface


def test_npcap_status_detection():
    """Verify Npcap status detection function."""
    status = InterfaceManager.check_npcap_status()
    assert isinstance(status, dict)
    assert "installed" in status
    assert "permission_granted" in status
    assert "message" in status


def test_packet_capture_worker_mock_aggregation():
    """Verify safe in-memory packet aggregation using mock packets."""
    worker = PacketCaptureWorker(interface_name="MockLoopback")
    
    # Feed controlled packets
    worker.feed_mock_packet(proto="TCP", length=1400, flow=("192.168.1.5", "1.1.1.1", 54321, 443, "TCP"))
    worker.feed_mock_packet(proto="TCP", length=600, flow=("192.168.1.5", "1.1.1.1", 54321, 443, "TCP"))
    worker.feed_mock_packet(proto="UDP", length=200, flow=("192.168.1.5", "8.8.8.8", 61000, 53, "UDP"))
    worker.feed_mock_packet(proto="ICMP", length=64, flow=("192.168.1.5", "8.8.4.4", 0, 0, "ICMP"))

    snap = worker.snapshot_and_reset()

    assert snap["scapy_packets"] == 4
    assert snap["scapy_bytes"] == 1400 + 600 + 200 + 64
    assert snap["tcp_count"] == 2
    assert snap["udp_count"] == 1
    assert snap["icmp_count"] == 1
    assert snap["unique_flows"] == 3
    assert snap["tcp_ratio"] == 0.5
    assert snap["avg_packet_size"] == round((1400 + 600 + 200 + 64) / 4, 1)

    # After reset, next snapshot must be zero
    snap2 = worker.snapshot_and_reset()
    assert snap2["scapy_packets"] == 0
    assert snap2["unique_flows"] == 0


def test_demo_traffic_generation():
    """Ensure Demo Mode produces valid telemetry with proper metadata."""
    demo_low = generate_demo_traffic(scenario="normal", tick=1)
    assert demo_low["capture_mode"] == "demo"
    assert demo_low["is_live"] is False
    assert demo_low["download_mbps"] > 0
    assert demo_low["packets_per_sec"] > 0
    assert demo_low["latency_ms"] < 60  # Healthy latency

    demo_high = generate_demo_traffic(scenario="high", tick=1)
    assert demo_high["capture_mode"] == "demo"
    assert demo_high["download_mbps"] > demo_low["download_mbps"]
    assert demo_high["latency_ms"] > 100  # Congested latency
