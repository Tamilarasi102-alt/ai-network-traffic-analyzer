"""
Unit Tests for Machine Learning Training, Validation, and Congestion Inference Pipelines.
"""
import pytest
import pandas as pd
import numpy as np
from pathlib import Path

import config
from ml.feature_schema import (
    FEATURE_COLUMNS,
    TARGET_COLUMN,
    CLASS_LABELS,
    validate_training_dataset
)
from ml.predictor import CongestionPredictor, RuleBasedCongestionEvaluator
from ml.trainer import generate_bootstrap_demo_dataset, train_and_evaluate_model


def test_validate_training_dataset():
    """Verify training dataset validation rules."""
    # 1. Valid DataFrame
    valid_data = []
    for label in CLASS_LABELS:
        for _ in range(10):
            row = {col: 10.0 for col in FEATURE_COLUMNS}
            row[TARGET_COLUMN] = label
            valid_data.append(row)
    df_valid = pd.DataFrame(valid_data)
    res = validate_training_dataset(df_valid)
    assert res["valid"] is True
    assert res["total_samples"] == 30

    # 2. Missing target column
    df_no_target = df_valid.drop(columns=[TARGET_COLUMN])
    res_no_target = validate_training_dataset(df_no_target)
    assert res_no_target["valid"] is False
    assert any("Missing target" in issue for issue in res_no_target["issues"])

    # 3. Missing feature column
    df_missing_feat = df_valid.drop(columns=["download_mbps"])
    res_missing_feat = validate_training_dataset(df_missing_feat)
    assert res_missing_feat["valid"] is False
    assert any("Missing required feature" in issue for issue in res_missing_feat["issues"])


def test_rule_based_congestion_evaluator():
    """Verify rule-based baseline thresholds."""
    # Low Congestion traffic
    stats_low = {
        "download_mbps": 5.0,
        "upload_mbps": 1.0,
        "packets_per_sec": 120,
        "bandwidth_util_percent": 6.0,
        "latency_ms": 22.0,
        "packet_loss_pct": 0.0
    }
    status_low, expl_low, recomms_low = RuleBasedCongestionEvaluator.evaluate(stats_low)
    assert status_low == "Low Congestion"
    assert "normally" in expl_low.lower()
    assert len(recomms_low) > 0

    # High Congestion traffic
    stats_high = {
        "download_mbps": 95.0,
        "upload_mbps": 30.0,
        "packets_per_sec": 5000,
        "bandwidth_util_percent": 88.0,
        "latency_ms": 250.0,
        "packet_loss_pct": 14.0
    }
    status_high, expl_high, recomms_high = RuleBasedCongestionEvaluator.evaluate(stats_high)
    assert status_high == "High Congestion"
    assert "high congestion" in expl_high.lower()
    assert len(recomms_high) > 0


def test_ml_prediction_pipeline():
    """Verify CongestionPredictor inference, probabilities, and schema adherence."""
    predictor = CongestionPredictor()
    # Predictor should either use ML model or fallback to rule-based engine cleanly
    raw_stats = {
        "download_mbps": 12.0,
        "upload_mbps": 2.5,
        "packets_per_sec": 250,
        "avg_packet_size": 750,
        "bandwidth_util_percent": 15.0,
        "latency_ms": 28.0,
        "jitter_ms": 1.8,
        "packet_loss_pct": 0.0,
        "tcp_ratio": 0.8,
        "udp_ratio": 0.15,
        "icmp_ratio": 0.05,
        "unique_flows": 12
    }

    pred = predictor.predict(raw_stats)

    assert "status" in pred
    assert pred["status"] in CLASS_LABELS
    assert pred["severity"] in ("LOW", "MEDIUM", "HIGH")
    assert pred["source"] in ("ML_MODEL", "RULE_BASED")
    assert "explanation" in pred
    assert "recommendations" in pred
    assert isinstance(pred["recommendations"], list)

    if pred["source"] == "ML_MODEL":
        assert pred["confidence"] is not None
        assert 0.0 <= pred["confidence"] <= 1.0
        assert pred["probabilities"] is not None
        prob_sum = sum(pred["probabilities"].values())
        assert abs(prob_sum - 1.0) < 0.02
