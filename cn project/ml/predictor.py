"""
Congestion Predictor and Rule-Based Evaluator.
Integrates trained Random Forest model with a robust, documented fallback rule-based engine.
"""
import json
import logging
from typing import Dict, Any, Optional, Tuple, List
import joblib
import numpy as np
import pandas as pd

import config
from ml.feature_schema import (
    FEATURE_COLUMNS,
    CLASS_LABELS,
    extract_features_from_dict,
    sanitize_feature_value
)

logger = logging.getLogger(__name__)


class RuleBasedCongestionEvaluator:
    """
    Documented rule-based baseline evaluator for network congestion.
    Used when an ML model is not yet trained or as a sanity check.
    """

    @staticmethod
    def evaluate(stats: Dict[str, Any]) -> Tuple[str, str, List[str]]:
        """
        Evaluate traffic metrics against configured thresholds.
        Returns:
            (status_str, explanation, recommendations)
        """
        download_mbps = sanitize_feature_value("download_mbps", stats.get("download_mbps"))
        upload_mbps = sanitize_feature_value("upload_mbps", stats.get("upload_mbps"))
        total_mbps = download_mbps + upload_mbps
        pps = sanitize_feature_value("packets_per_sec", stats.get("packets_per_sec"))
        latency = stats.get("latency_ms")
        jitter = stats.get("jitter_ms")
        loss = stats.get("packet_loss_pct")
        util = stats.get("bandwidth_util_percent")

        latency_val = sanitize_feature_value("latency_ms", latency) if latency is not None else None
        loss_val = sanitize_feature_value("packet_loss_pct", loss) if loss is not None else None
        util_val = sanitize_feature_value("bandwidth_util_percent", util) if util is not None else None

        high_cfg = config.CONGESTION_THRESHOLDS["HIGH"]
        med_cfg = config.CONGESTION_THRESHOLDS["MEDIUM"]

        high_reasons = []
        med_reasons = []

        # High Congestion evaluation
        if util_val is not None and util_val >= high_cfg["bandwidth_util_pct"]:
            high_reasons.append(f"Bandwidth utilization is critical ({util_val:.1f}%)")
        if loss_val is not None and loss_val >= high_cfg["packet_loss_pct"]:
            high_reasons.append(f"Severe packet loss detected ({loss_val:.1f}%)")
        if latency_val is not None and latency_val >= high_cfg["latency_ms"]:
            high_reasons.append(f"High round-trip latency ({latency_val:.1f} ms)")
        if total_mbps >= high_cfg["throughput_mbps"] and pps >= high_cfg["pps"]:
            high_reasons.append(f"Massive network throughput ({total_mbps:.1f} Mbps at {pps:.0f} PPS)")

        if high_reasons:
            explanation = "High congestion detected: " + "; ".join(high_reasons) + ". Bufferbloat or bottleneck link saturation likely."
            recomms = [
                "Identify and limit heavy download/upload processes (torrents, file transfers, cloud backups).",
                "Enable Smart Queue Management (SQM) / Cake / FQ-CoDel on router if available.",
                "Switch to 5GHz Wi-Fi or wired Gigabit Ethernet to reduce wireless collision."
            ]
            return "High Congestion", explanation, recomms

        # Medium Congestion evaluation
        if util_val is not None and util_val >= med_cfg["bandwidth_util_pct"]:
            med_reasons.append(f"Moderate bandwidth utilization ({util_val:.1f}%)")
        if loss_val is not None and loss_val >= med_cfg["packet_loss_pct"]:
            med_reasons.append(f"Noticeable packet loss ({loss_val:.1f}%)")
        if latency_val is not None and latency_val >= med_cfg["latency_ms"]:
            med_reasons.append(f"Elevated latency ({latency_val:.1f} ms)")
        if total_mbps >= med_cfg["throughput_mbps"]:
            med_reasons.append(f"Moderate-to-high throughput ({total_mbps:.1f} Mbps)")

        if med_reasons:
            explanation = "Medium congestion observed: " + "; ".join(med_reasons) + ". Traffic load is noticeable but within manageable margins."
            recomms = [
                "Monitor active streaming or high-bandwidth video conference streams.",
                "Verify if background updates (Windows Update, game launchers) are active.",
                "Ensure Wi-Fi signal strength is adequate."
            ]
            return "Medium Congestion", explanation, recomms

        # Low Congestion (Normal)
        explanation = f"Network is operating normally. Throughput: {total_mbps:.2f} Mbps, PPS: {pps:.0f}."
        if latency_val is not None:
            explanation += f" Latency is healthy at {latency_val:.1f} ms."
        recomms = [
            "Network conditions optimal. No remediation required."
        ]
        return "Low Congestion", explanation, recomms


class CongestionPredictor:
    """
    Manages model loading, inference, and fallback to rule-based evaluation.
    """

    def __init__(self):
        self.model = None
        self.metadata = {}
        self.is_loaded = False
        self.load_model()

    def load_model(self) -> bool:
        """Attempt to load trained model and its metadata from disk."""
        if config.MODEL_PATH.exists() and config.METADATA_PATH.exists():
            try:
                self.model = joblib.load(config.MODEL_PATH)
                with open(config.METADATA_PATH, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                self.is_loaded = True
                logger.info("Successfully loaded ML model from %s", config.MODEL_PATH)
                return True
            except Exception as e:
                logger.error("Failed to load model from disk: %s", e)
                self.model = None
                self.metadata = {}
                self.is_loaded = False
                return False
        else:
            self.model = None
            self.metadata = {}
            self.is_loaded = False
            return False

    def predict(self, raw_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify network congestion using ML model when available,
        or fallback gracefully to RuleBasedCongestionEvaluator.
        """
        if self.is_loaded and self.model is not None:
            try:
                # Extract strict feature vector
                features_df = extract_features_from_dict(raw_stats)
                predicted_class = self.model.predict(features_df)[0]
                
                # Predict probabilities
                proba = self.model.predict_proba(features_df)[0]
                classes = list(self.model.classes_)
                
                prob_dict = {}
                for cls_name, p in zip(classes, proba):
                    prob_dict[cls_name] = round(float(p), 4)

                # Ensure all labels present in prob_dict
                for lbl in CLASS_LABELS:
                    if lbl not in prob_dict:
                        prob_dict[lbl] = 0.0

                max_confidence = round(float(np.max(proba)), 4)
                
                # Generate explanation and recommendations
                _, rule_expl, recomms = RuleBasedCongestionEvaluator.evaluate(raw_stats)

                is_demo = self.metadata.get("is_demo_model", True)
                model_type_tag = "Demo-Trained ML Model" if is_demo else "Real-Data Trained ML Model"

                severity = "LOW"
                if "medium" in predicted_class.lower():
                    severity = "MEDIUM"
                elif "high" in predicted_class.lower():
                    severity = "HIGH"

                explanation = (
                    f"[{model_type_tag}] Classified as {predicted_class} with {max_confidence * 100:.1f}% model confidence. "
                    f"Context: {rule_expl}"
                )

                return {
                    "status": predicted_class,
                    "severity": severity,
                    "source": "ML_MODEL",
                    "is_demo_model": is_demo,
                    "confidence": max_confidence,
                    "probabilities": prob_dict,
                    "explanation": explanation,
                    "recommendations": recomms,
                    "model_name": self.metadata.get("model_name", "Random Forest Classifier"),
                    "feature_values": features_df.to_dict(orient="records")[0]
                }
            except Exception as e:
                logger.warning("ML prediction failed; falling back to rule-based engine: %s", e)

        # Fallback to rule-based evaluation
        status, explanation, recomms = RuleBasedCongestionEvaluator.evaluate(raw_stats)
        severity = "LOW"
        if "medium" in status.lower():
            severity = "MEDIUM"
        elif "high" in status.lower():
            severity = "HIGH"

        return {
            "status": status,
            "severity": severity,
            "source": "RULE_BASED",
            "is_demo_model": False,
            "confidence": None,
            "probabilities": None,
            "explanation": f"[Rule-Based Baseline] {explanation}",
            "recommendations": recomms,
            "model_name": "Rule-Based Threshold Engine",
            "feature_values": extract_features_from_dict(raw_stats).to_dict(orient="records")[0]
        }
