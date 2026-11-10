"""
Configuration settings for AI Network Traffic Analyzer and Congestion Prediction System.
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure runtime directories exist
DATA_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# Data File Paths
DEMO_DATA_PATH = DATA_DIR / "demo_training_data.csv"
LIVE_DATA_PATH = DATA_DIR / "live_observations.csv"
LABELLED_DATA_PATH = DATA_DIR / "labelled_observations.csv"

# Model File Paths
MODEL_PATH = MODELS_DIR / "congestion_rf_model.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

# Server Settings
HOST = "127.0.0.1"
PORT = 5000
DEBUG = False

# Monitoring Parameters
MONITORING_INTERVAL_SECONDS = 1.0
MEASUREMENT_WINDOW_SECONDS = 5.0
HISTORY_BUFFER_MAXLEN = 60

# Active Latency Ping Parameters
DEFAULT_PING_TARGET = "8.8.8.8"
PING_TIMEOUT_MS = 1000
PING_WINDOW_SIZE = 10

# Rule-Based Congestion Thresholds (Configurable)
CONGESTION_THRESHOLDS = {
    "HIGH": {
        "bandwidth_util_pct": 80.0,    # If interface speed is known
        "latency_ms": 180.0,           # High latency
        "packet_loss_pct": 10.0,       # High packet loss
        "pps": 4000.0,                 # High packet rate fallback
        "throughput_mbps": 80.0        # High throughput fallback
    },
    "MEDIUM": {
        "bandwidth_util_pct": 45.0,
        "latency_ms": 75.0,
        "packet_loss_pct": 2.5,
        "pps": 1500.0,
        "throughput_mbps": 25.0
    }
}

# Alert State Management
ALERT_COOLDOWN_SECONDS = 8
