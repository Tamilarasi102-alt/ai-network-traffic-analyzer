"""
Machine Learning Feature Schema and Validation.
Ensures strict consistency between the data pipeline, model training, and real-time inference.
"""
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd

# Canonical feature list in strict order
FEATURE_COLUMNS: List[str] = [
    "download_mbps",
    "upload_mbps",
    "packets_per_sec",
    "avg_packet_size",
    "bandwidth_util_percent",
    "latency_ms",
    "jitter_ms",
    "packet_loss_pct",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "unique_flows"
]

TARGET_COLUMN = "congestion_level"

CLASS_LABELS: List[str] = [
    "Low Congestion",
    "Medium Congestion",
    "High Congestion"
]

# Imputation defaults when a metric cannot be measured or is None
DEFAULT_IMPUTATION: Dict[str, float] = {
    "download_mbps": 0.0,
    "upload_mbps": 0.0,
    "packets_per_sec": 0.0,
    "avg_packet_size": 512.0,       # Typical Ethernet payload midpoint
    "bandwidth_util_percent": 0.0,   # Safe default if interface speed unknown
    "latency_ms": 25.0,             # Typical healthy baseline latency
    "jitter_ms": 2.0,               # Typical baseline jitter
    "packet_loss_pct": 0.0,         # Normal baseline
    "tcp_ratio": 0.70,              # Standard web-dominated traffic
    "udp_ratio": 0.25,
    "icmp_ratio": 0.05,
    "unique_flows": 5.0
}


def sanitize_feature_value(key: str, val: Any) -> float:
    """
    Sanitize and convert an individual feature value to float.
    Handles None, strings ('N/A', 'Unavailable'), NaN, and negative values.
    """
    if val is None:
        return DEFAULT_IMPUTATION.get(key, 0.0)
    if isinstance(val, str):
        val_clean = val.strip().lower()
        if val_clean in ("n/a", "unavailable", "none", "", "nan"):
            return DEFAULT_IMPUTATION.get(key, 0.0)
        try:
            val = float(val)
        except ValueError:
            return DEFAULT_IMPUTATION.get(key, 0.0)
    try:
        f_val = float(val)
        if np.isnan(f_val) or np.isinf(f_val):
            return DEFAULT_IMPUTATION.get(key, 0.0)
        return max(0.0, f_val)
    except (TypeError, ValueError):
        return DEFAULT_IMPUTATION.get(key, 0.0)


def extract_features_from_dict(raw_stats: Dict[str, Any]) -> pd.DataFrame:
    """
    Extract a single-row DataFrame matching FEATURE_COLUMNS from a live statistics dictionary.
    Guarantees strict schema adherence and column ordering.
    """
    row = {}
    for col in FEATURE_COLUMNS:
        raw_val = raw_stats.get(col)
        row[col] = sanitize_feature_value(col, raw_val)
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)


def validate_training_dataset(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Validates a training DataFrame before fitting a model.
    Checks required columns, missing values, and class distribution.
    """
    issues = []
    
    # Check required columns
    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_features:
        issues.append(f"Missing required feature columns: {missing_features}")
    
    if TARGET_COLUMN not in df.columns:
        issues.append(f"Missing target column: '{TARGET_COLUMN}'")
        return {"valid": False, "issues": issues}

    # Drop nulls in target
    valid_rows = df.dropna(subset=[TARGET_COLUMN])
    if len(valid_rows) < 15:
        issues.append(f"Insufficient training rows ({len(valid_rows)}). Minimum 15 required.")

    # Check class distribution
    class_counts = valid_rows[TARGET_COLUMN].value_counts().to_dict()
    for label in CLASS_LABELS:
        count = class_counts.get(label, 0)
        if count < 3:
            issues.append(f"Class '{label}' has only {count} samples (minimum 3 required for stratification).")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "total_samples": len(valid_rows),
        "class_distribution": class_counts
    }
