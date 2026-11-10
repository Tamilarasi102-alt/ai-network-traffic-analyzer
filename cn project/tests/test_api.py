"""
Integration Tests for Flask Web Application Endpoints and Control APIs.
"""
import json
import pytest
from app import app, manager


@pytest.fixture
def client():
    """Create Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_route(client):
    """Verify home page loads successfully."""
    res = client.get("/")
    assert res.status_code == 200
    assert b"AI Network Traffic Analyzer" in res.data


def test_api_health(client):
    """Verify /api/health endpoint structure."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert "monitoring_active" in data
    assert "mode" in data
    assert "interface" in data
    assert "npcap" in data


def test_api_interfaces(client):
    """Verify /api/interfaces returns valid interfaces list."""
    res = client.get("/api/interfaces")
    assert res.status_code == 200
    data = res.get_json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)
    assert "recommended_interface" in data
    assert "npcap" in data


def test_api_mode_switch(client):
    """Verify switching between Demo and Live modes."""
    # Switch to demo
    res = client.post("/api/mode", json={"mode": "demo"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["mode"] == "demo"

    # Invalid mode
    res_bad = client.post("/api/mode", json={"mode": "invalid_mode"})
    assert res_bad.status_code == 400


def test_api_demo_scenario(client):
    """Verify setting demo traffic scenarios."""
    res = client.post("/api/demo/scenario", json={"scenario": "high"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    # Bad scenario
    res_bad = client.post("/api/demo/scenario", json={"scenario": "nonexistent"})
    assert res_bad.status_code == 400


def test_api_monitor_lifecycle(client):
    """Verify start and stop monitor controls."""
    # Ensure stopped initially
    manager.stop()

    # Start in demo mode
    start_res = client.post("/api/monitor/start", json={"mode": "demo"})
    assert start_res.status_code == 200
    assert manager.is_running is True

    # Duplicate start check
    dup_res = client.post("/api/monitor/start", json={"mode": "demo"})
    assert dup_res.status_code == 400
    assert "already active" in dup_res.get_json()["message"]

    # Stop monitor
    stop_res = client.post("/api/monitor/stop")
    assert stop_res.status_code == 200
    assert manager.is_running is False


def test_api_predict_custom(client):
    """Verify /api/predict accepts custom payload."""
    payload = {
        "download_mbps": 85.0,
        "upload_mbps": 30.0,
        "packets_per_sec": 4200,
        "avg_packet_size": 1200,
        "bandwidth_util_percent": 90.0,
        "latency_ms": 220.0,
        "jitter_ms": 35.0,
        "packet_loss_pct": 12.0,
        "tcp_ratio": 0.6,
        "udp_ratio": 0.35,
        "icmp_ratio": 0.05,
        "unique_flows": 80
    }
    res = client.post("/api/predict", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "prediction" in data
    assert data["prediction"]["status"] in ("Low Congestion", "Medium Congestion", "High Congestion")


def test_api_observations_label(client):
    """Verify saving a user-labelled observation."""
    payload = {
        "label": "Low Congestion",
        "features": {
            "download_mbps": 4.5,
            "upload_mbps": 1.2,
            "packets_per_sec": 100,
            "avg_packet_size": 600,
            "bandwidth_util_percent": 5.0,
            "latency_ms": 20.0,
            "jitter_ms": 1.5,
            "packet_loss_pct": 0.0,
            "tcp_ratio": 0.85,
            "udp_ratio": 0.1,
            "icmp_ratio": 0.05,
            "unique_flows": 6
        }
    }
    res = client.post("/api/observations/label", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "total_labelled_samples" in data


def test_api_export_csv(client):
    """Verify /api/export returns CSV content."""
    res = client.get("/api/export")
    # Should either return CSV attachment (200) or 404 if no data
    assert res.status_code in (200, 404)
    if res.status_code == 200:
        assert "text/csv" in res.content_type


def test_api_analysis_deep(client):
    """Verify deep analytical statistics endpoint."""
    res = client.get("/api/analysis/deep?time_window=all&severity=all&protocol=all")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    ana = data["analysis"]
    assert "download_stats" in ana
    assert "latency_stats" in ana
    assert "correlation_throughput_latency" in ana
    assert "sla_compliance_percent" in ana
    assert "feature_importance" in ana
    assert "table_rows" in ana


def test_api_trigger_execute(client):
    """Verify trigger execution (diagnostic burst and stress injection)."""
    # 1. Diagnostic burst
    res = client.post("/api/trigger/execute", json={"action": "diagnostic_burst", "target": "8.8.8.8"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    trig = data["trigger"]
    assert trig["action"] == "diagnostic_burst"
    assert trig["status"] in ("Triggered", "Failed")
    assert "logs" in trig
    assert len(trig["logs"]) > 0

    # 2. Stress injection
    res_stress = client.post("/api/trigger/execute", json={"action": "stress_injection"})
    assert res_stress.status_code == 200
    data_stress = res_stress.get_json()
    assert data_stress["success"] is True
    assert data_stress["trigger"]["status"] == "Triggered"


def test_api_trigger_status(client):
    """Verify trigger status tracking endpoint."""
    res = client.get("/api/trigger/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "latest_trigger" in data
    assert "history" in data


def test_api_report_generate(client):
    """Verify dynamic audit report generation."""
    res = client.get("/api/report/generate")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    rep = data["report"]
    assert "report_id" in rep
    assert "sla_score" in rep
    assert "model_accuracy" in rep
    assert "recommendation" in rep


def test_api_report_download(client):
    """Verify report HTML printable download."""
    res = client.get("/api/report/download")
    assert res.status_code == 200
    assert "text/html" in res.content_type
    assert b"AI Network Telemetry & Congestion Audit Report" in res.data


def test_api_settings(client):
    """Verify GET and POST settings configuration."""
    # GET
    res_get = client.get("/api/settings")
    assert res_get.status_code == 200
    data_get = res_get.get_json()
    assert data_get["success"] is True
    assert "ping_target" in data_get["settings"]

    # POST
    payload = {
        "ping_target": "1.1.1.1",
        "polling_interval": 1.5,
        "audio_alerts_enabled": True,
        "high_latency_threshold": 160.0,
        "high_loss_threshold": 8.0
    }
    res_post = client.post("/api/settings", json=payload)
    assert res_post.status_code == 200
    data_post = res_post.get_json()
    assert data_post["success"] is True
    assert data_post["settings"]["ping_target"] == "1.1.1.1"
    assert data_post["settings"]["polling_interval"] == 1.5

