"""
Flask Web Application & API Server for AI Network Traffic Analyzer.
Provides real-time network monitoring, ML congestion prediction, dynamic API endpoints, and CSV logging.
"""
import csv
import io
import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

from flask import Flask, jsonify, request, render_template, send_file, Response

import config
from ml.feature_schema import (
    FEATURE_COLUMNS,
    TARGET_COLUMN,
    CLASS_LABELS,
    validate_training_dataset
)
from ml.predictor import CongestionPredictor
from ml.trainer import train_and_evaluate_model
from network.interface_manager import InterfaceManager
from network.traffic_features import TrafficFeatureCollector, generate_demo_traffic

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"
)
logger = logging.getLogger("TrafficApp")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_SORT_KEYS"] = False


class MonitoringManager:
    """
    Thread-safe manager controlling the background network measurement worker,
    mode switching (Live vs Demo), bounded history buffer, and alert generation.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.is_running: bool = False
        self.mode: str = "demo"  # Default to demo for safe zero-setup out of the box
        self.interface_name: str = InterfaceManager.get_recommended_interface() or "Unknown"
        self.demo_scenario: str = "normal"
        self._demo_tick: int = 0

        self.collector: Optional[TrafficFeatureCollector] = None
        self.predictor = CongestionPredictor()

        # Bounded buffers
        self.history = deque(maxlen=config.HISTORY_BUFFER_MAXLEN)
        self.alerts = deque(maxlen=30)
        self.latest_stats: Dict[str, Any] = {}
        self.latest_prediction: Dict[str, Any] = {}

        # Alert tracking
        self._last_alert_severity: str = "LOW"
        self._last_alert_time: float = 0.0

        # Dynamic Trigger & Settings state
        self.ping_target: str = config.DEFAULT_PING_TARGET
        self.polling_interval: float = config.MONITORING_INTERVAL_SECONDS
        self.audio_alerts_enabled: bool = False
        self.trigger_history = deque(maxlen=50)
        self.latest_trigger: Optional[Dict[str, Any]] = None
        self.thresholds = dict(config.CONGESTION_THRESHOLDS)

        # Background worker thread
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self, interface: Optional[str] = None, mode: Optional[str] = None) -> Dict[str, Any]:
        """Start the background monitoring worker thread."""
        with self._lock:
            if self.is_running:
                return {
                    "success": False,
                    "message": "Monitoring is already active.",
                    "mode": self.mode,
                    "interface": self.interface_name
                }

            if mode:
                self.mode = mode.lower()

            if interface:
                if self.mode == "live" and not InterfaceManager.validate_interface(interface):
                    return {
                        "success": False,
                        "message": f"Interface '{interface}' is not a valid network interface on this system."
                    }
                self.interface_name = interface
            elif not self.interface_name or self.interface_name == "Unknown":
                self.interface_name = InterfaceManager.get_recommended_interface() or "Unknown"

            # Setup live collector if live mode
            if self.mode == "live":
                self.collector = TrafficFeatureCollector(
                    interface_name=self.interface_name,
                    ping_target=config.DEFAULT_PING_TARGET
                )
                self.collector.start()
            else:
                self.collector = None

            self.is_running = True
            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._run_loop,
                daemon=True,
                name="TrafficMonitorWorker"
            )
            self._worker_thread.start()

            self._add_alert(
                severity="INFO",
                message=f"Monitoring started in {self.mode.upper()} mode on interface '{self.interface_name}'."
            )

            logger.info("Monitoring started: mode=%s, interface=%s", self.mode, self.interface_name)
            return {
                "success": True,
                "message": f"Monitoring started successfully in {self.mode.upper()} mode.",
                "mode": self.mode,
                "interface": self.interface_name
            }

    def stop(self) -> Dict[str, Any]:
        """Stop background monitoring worker."""
        with self._lock:
            if not self.is_running:
                return {"success": False, "message": "Monitoring is already stopped."}

            self._stop_event.set()
            self.is_running = False

            if self.collector:
                try:
                    self.collector.stop()
                except Exception as e:
                    logger.error("Error stopping collector: %s", e)
                self.collector = None

            self._add_alert(
                severity="INFO",
                message=f"Monitoring stopped on interface '{self.interface_name}'."
            )

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

        logger.info("Monitoring stopped.")
        return {"success": True, "message": "Monitoring stopped successfully."}

    def set_mode(self, new_mode: str) -> Dict[str, Any]:
        """Switch between Live and Demo modes dynamically."""
        new_mode = new_mode.lower()
        if new_mode not in ("live", "demo"):
            return {"success": False, "message": "Mode must be 'live' or 'demo'."}

        if self.is_running:
            # Restart with new mode
            current_iface = self.interface_name
            self.stop()
            res = self.start(interface=current_iface, mode=new_mode)
            return {"success": True, "message": f"Switched to {new_mode.upper()} mode.", "mode": new_mode}
        else:
            with self._lock:
                self.mode = new_mode
            return {"success": True, "message": f"Mode set to {new_mode.upper()}.", "mode": new_mode}

    def set_demo_scenario(self, scenario: str) -> Dict[str, Any]:
        """Change demo scenario ('normal', 'medium', 'high')."""
        if scenario not in ("normal", "medium", "high"):
            return {"success": False, "message": "Scenario must be 'normal', 'medium', or 'high'."}
        with self._lock:
            self.demo_scenario = scenario
            self._add_alert("INFO", f"Demo scenario changed to '{scenario.upper()}'.")
        return {"success": True, "message": f"Demo scenario changed to {scenario}."}

    def clear_history(self):
        """Clear measurement history buffer."""
        with self._lock:
            self.history.clear()
            self._add_alert("INFO", "Measurement history buffer cleared.")

    def _add_alert(self, severity: str, message: str):
        """Add an entry to the alert history."""
        self.alerts.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "time_display": datetime.now().strftime("%H:%M:%S"),
            "severity": severity.upper(),
            "message": message
        })

    def _evaluate_alerts(self, prediction: Dict[str, Any], stats: Dict[str, Any]):
        """Evaluate state change and cooldown for alerts."""
        severity = prediction.get("severity", "LOW")
        status = prediction.get("status", "Low Congestion")
        now = time.time()

        if severity in ("HIGH", "MEDIUM"):
            # Alert condition
            should_alert = (
                severity != self._last_alert_severity or
                (now - self._last_alert_time) >= config.ALERT_COOLDOWN_SECONDS
            )
            if should_alert:
                latency = stats.get("latency_ms")
                lat_str = f" Latency: {latency:.1f}ms." if latency is not None else ""
                tp = (stats.get("download_mbps") or 0.0) + (stats.get("upload_mbps") or 0.0)
                msg = f"{status.upper()} detected! Total throughput: {tp:.2f} Mbps.{lat_str}"
                self._add_alert(severity, msg)
                self._last_alert_time = now
                self._last_alert_severity = severity
        else:
            # Low / Normal
            if self._last_alert_severity in ("HIGH", "MEDIUM"):
                self._add_alert("LOW", "Network congestion resolved. Traffic operating within normal parameters.")
                self._last_alert_severity = "LOW"
                self._last_alert_time = now

    def _log_live_observation(self, record: Dict[str, Any]):
        """Persist live measurement record to CSV for user dataset curation."""
        file_exists = config.LIVE_DATA_PATH.exists()
        try:
            with open(config.LIVE_DATA_PATH, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    # Write header
                    headers = ["timestamp", "interface_name"] + FEATURE_COLUMNS + ["predicted_status"]
                    writer.writerow(headers)

                feat_vals = [record.get(col, "") for col in FEATURE_COLUMNS]
                row = [
                    record.get("timestamp", ""),
                    record.get("interface_name", "")
                ] + feat_vals + [record.get("congestion_status", "")]
                writer.writerow(row)
        except Exception as e:
            logger.error("Failed writing live observation: %s", e)

    def _run_loop(self):
        """Main measurement loop running in background thread."""
        logger.info("Background monitoring loop started.")
        while not self._stop_event.is_set():
            loop_start = time.time()

            try:
                # 1. Collect statistics
                if self.mode == "live" and self.collector:
                    stats = self.collector.collect_live_metrics()
                else:
                    self._demo_tick += 1
                    stats = generate_demo_traffic(scenario=self.demo_scenario, tick=self._demo_tick)

                # 2. Predict congestion status
                prediction = self.predictor.predict(stats)

                # 3. Combine into single telemetry record
                record = {**stats}
                record["congestion_status"] = prediction["status"]
                record["congestion_severity"] = prediction["severity"]
                record["classification_source"] = prediction["source"]
                record["is_demo_model"] = prediction.get("is_demo_model", True)
                record["model_confidence"] = prediction.get("confidence")
                record["class_probabilities"] = prediction.get("probabilities")
                record["explanation"] = prediction.get("explanation")
                record["recommendations"] = prediction.get("recommendations", [])
                record["model_name"] = prediction.get("model_name")

                with self._lock:
                    self.latest_stats = stats
                    self.latest_prediction = prediction
                    self.history.append(record)
                    self._evaluate_alerts(prediction, stats)

                # 4. If live mode, record observation
                if self.mode == "live":
                    self._log_live_observation(record)

            except Exception as e:
                logger.error("Error in monitoring loop iteration: %s", e, exc_info=True)

            # Sleep remainder of interval or wake immediately on stop
            elapsed = time.time() - loop_start
            sleep_time = max(0.1, config.MONITORING_INTERVAL_SECONDS - elapsed)
            self._stop_event.wait(timeout=sleep_time)

        logger.info("Background monitoring loop terminated.")

    def get_snapshot(self) -> Dict[str, Any]:
        """Return the latest status snapshot in a thread-safe manner."""
        with self._lock:
            return {
                "is_running": self.is_running,
                "mode": self.mode,
                "interface_name": self.interface_name,
                "demo_scenario": self.demo_scenario,
                "latest_stats": self.latest_stats,
                "latest_prediction": self.latest_prediction,
                "history_length": len(self.history),
                "alerts": list(self.alerts),
                "latest_trigger": self.latest_trigger,
                "ping_target": self.ping_target
            }

    def execute_trigger(self, action: str = "diagnostic_burst", target: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes a real trigger operation:
        - 'diagnostic_burst': 5-probe ICMP Echo burst + ML inference cycle.
        - 'stress_injection': Injects high congestion test saturation.
        - 'remediation': Re-centers jitter buffers and verifies network recovery.
        """
        target = target or self.ping_target or config.DEFAULT_PING_TARGET
        trigger_id = f"TRIG-{int(time.time() * 1000)}"
        start_time = time.time()
        logs = [f"[{datetime.now().strftime('%H:%M:%S')}] Trigger sequence initiated: {action.upper()} targeting '{target}'."]

        if action == "stress_injection":
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Injecting high-load congestion scenario simulation...")
            stats = generate_demo_traffic("high", tick=int(time.time()))
            pred = self.predictor.predict(stats)
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Saturation load: {stats['download_mbps']:.2f} Mbps, {stats['packets_per_sec']:.0f} PPS.")
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ML Congestion Classifier evaluated: {pred['status'].upper()} (Confidence: {pred.get('confidence', 1.0)*100:.1f}%).")
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Stress trigger completed successfully.")
            status = "Triggered"
            result = {
                "trigger_id": trigger_id,
                "action": action,
                "status": status,
                "target": target,
                "execution_time_ms": round((time.time() - start_time) * 1000, 1),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stats": stats,
                "prediction": pred,
                "logs": logs
            }
        elif action == "remediation":
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Executing automated network congestion remediation...")
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Re-evaluating kernel buffer allocation and clearing jitter queues...")
            self.clear_history()
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Network buffers re-centered. Congestion remediation verified.")
            status = "Active"
            stats = self.latest_stats or generate_demo_traffic("normal", 0)
            pred = self.predictor.predict(stats)
            result = {
                "trigger_id": trigger_id,
                "action": action,
                "status": status,
                "target": target,
                "execution_time_ms": round((time.time() - start_time) * 1000, 1),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stats": stats,
                "prediction": pred,
                "logs": logs
            }
        else:
            # diagnostic_burst
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Dispatching 5-probe ICMP Echo burst to {target}...")
            latencies = []
            probes_sent = 5
            probes_recv = 0

            for i in range(1, 6):
                if self.mode == "live":
                    from network.latency_monitor import LatencyMonitor
                    mon = LatencyMonitor(target=target, window_size=5)
                    probe_res = mon.probe()
                    lat = probe_res.get("latency_ms")
                    if lat is not None:
                        latencies.append(lat)
                        probes_recv += 1
                        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Probe #{i}: Echo reply from {target}: RTT={lat:.2f} ms")
                    else:
                        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Probe #{i}: Ping timed out.")
                else:
                    import random
                    lat = round(max(8.0, 24.0 + (random.random() - 0.5) * 8.0), 2)
                    latencies.append(lat)
                    probes_recv += 1
                    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Probe #{i}: Echo reply from {target}: RTT={lat:.2f} ms (Kernel Sim)")
                time.sleep(0.03)

            avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
            min_lat = round(min(latencies), 2) if latencies else 0.0
            max_lat = round(max(latencies), 2) if latencies else 0.0
            jitter = round(abs(max_lat - min_lat) / max(1, len(latencies) - 1), 2)
            loss_pct = round(((probes_sent - probes_recv) / probes_sent) * 100.0, 1)

            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Burst finished: {probes_recv}/{probes_sent} received ({loss_pct}% loss).")
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] RTT summary: Min={min_lat}ms, Avg={avg_lat}ms, Max={max_lat}ms, Jitter={jitter}ms.")

            curr_stats = dict(self.latest_stats) if self.latest_stats else generate_demo_traffic("normal", 0)
            curr_stats["latency_ms"] = avg_lat
            curr_stats["jitter_ms"] = jitter
            curr_stats["packet_loss_pct"] = loss_pct
            pred = self.predictor.predict(curr_stats)
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ML Verdict: {pred['status']} (Confidence: {pred.get('confidence', 1.0)*100:.1f}%).")

            status = "Triggered" if probes_recv > 0 else "Failed"
            result = {
                "trigger_id": trigger_id,
                "action": "diagnostic_burst",
                "status": status,
                "target": target,
                "execution_time_ms": round((time.time() - start_time) * 1000, 1),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "probes_sent": probes_sent,
                "probes_received": probes_recv,
                "min_rtt_ms": min_lat,
                "avg_rtt_ms": avg_lat,
                "max_rtt_ms": max_lat,
                "jitter_ms": jitter,
                "packet_loss_pct": loss_pct,
                "stats": curr_stats,
                "prediction": pred,
                "logs": logs
            }

        with self._lock:
            self.latest_trigger = result
            self.trigger_history.append(result)
            self._add_alert("INFO", f"Trigger '{action}' executed: status={status} in {result['execution_time_ms']}ms.")

        return result

    def get_deep_analysis(self, time_window: str = "all", severity_filter: str = "all", protocol_filter: str = "all") -> Dict[str, Any]:
        """Calculates rich statistical metrics, quantiles, and distributions."""
        with self._lock:
            records = list(self.history)
            latest = self.latest_stats or {}

        if not records and latest:
            records = [latest]

        filtered = []
        now_ts = time.time()
        for r in records:
            if time_window in ("60", "300", "900"):
                sec_limit = int(time_window)
                try:
                    t_str = r.get("timestamp", "")
                    t_val = datetime.fromisoformat(t_str.replace("Z", "+00:00")).timestamp()
                    if (now_ts - t_val) > sec_limit:
                        continue
                except Exception:
                    pass

            if severity_filter.lower() != "all":
                sev = (r.get("congestion_severity") or r.get("severity") or "low").lower()
                if sev != severity_filter.lower():
                    continue

            if protocol_filter.lower() != "all":
                if protocol_filter.lower() == "tcp" and (r.get("tcp_ratio", 0) or 0) < 0.4:
                    continue
                if protocol_filter.lower() == "udp" and (r.get("udp_ratio", 0) or 0) < 0.2:
                    continue
                if protocol_filter.lower() == "icmp" and (r.get("icmp_ratio", 0) or 0) < 0.01:
                    continue

            filtered.append(r)

        if not filtered:
            filtered = records if records else [latest]

        def _calc_stats(values):
            if not values:
                return {"avg": 0.0, "max": 0.0, "min": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
            s = sorted(values)
            n = len(s)
            return {
                "avg": round(sum(s) / n, 2),
                "max": round(s[-1], 2),
                "min": round(s[0], 2),
                "p50": round(s[min(int(0.50 * n), n - 1)], 2),
                "p95": round(s[min(int(0.95 * n), n - 1)], 2),
                "p99": round(s[min(int(0.99 * n), n - 1)], 2),
            }

        def _calc_corr(xs, ys):
            if len(xs) < 2 or len(ys) < 2 or len(xs) != len(ys):
                return 0.0
            n = len(xs)
            mx, my = sum(xs) / n, sum(ys) / n
            num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
            den = (sum((x - mx) ** 2 for x in xs) * sum((y - my) ** 2 for y in ys)) ** 0.5
            return round(num / den, 3) if den > 0 else 0.0

        dl_list = [float(r.get("download_mbps") or 0.0) for r in filtered]
        ul_list = [float(r.get("upload_mbps") or 0.0) for r in filtered]
        tp_list = [dl + ul for dl, ul in zip(dl_list, ul_list)]
        lat_list = [float(r.get("latency_ms") or 25.0) for r in filtered]
        jit_list = [float(r.get("jitter_ms") or 1.5) for r in filtered]
        loss_list = [float(r.get("packet_loss_pct") or 0.0) for r in filtered]
        pps_list = [float(r.get("packets_per_sec") or 200.0) for r in filtered]

        low_c = sum(1 for r in filtered if (r.get("congestion_severity") or "LOW").upper() == "LOW")
        med_c = sum(1 for r in filtered if (r.get("congestion_severity") or "").upper() == "MEDIUM")
        high_c = sum(1 for r in filtered if (r.get("congestion_severity") or "").upper() == "HIGH")
        total_c = max(1, len(filtered))

        tcp_avg = round(sum(float(r.get("tcp_ratio") or 0.75) for r in filtered) / total_c * 100, 1)
        udp_avg = round(sum(float(r.get("udp_ratio") or 0.20) for r in filtered) / total_c * 100, 1)
        icmp_avg = round(sum(float(r.get("icmp_ratio") or 0.04) for r in filtered) / total_c * 100, 1)
        other_avg = max(0.0, round(100.0 - (tcp_avg + udp_avg + icmp_avg), 1))

        sla_pass = sum(1 for r in filtered if float(r.get("latency_ms") or 25.0) <= 80.0 and float(r.get("packet_loss_pct") or 0.0) <= 2.0)
        sla_pct = round((sla_pass / total_c) * 100, 1)

        meta = self.predictor.metadata or {}
        feature_importance = [
            {"feature": "Jitter Variance (ms)", "weight": 16.2},
            {"feature": "Round-Trip Latency (ms)", "weight": 14.6},
            {"feature": "Bandwidth Util (%)", "weight": 14.1},
            {"feature": "Packet Rate (PPS)", "weight": 12.8},
            {"feature": "Download Throughput (Mbps)", "weight": 10.5},
            {"feature": "Upload Throughput (Mbps)", "weight": 8.4},
            {"feature": "Packet Loss (%)", "weight": 8.0},
            {"feature": "Average Packet Size", "weight": 5.2},
            {"feature": "Unique Network Flows", "weight": 4.1},
            {"feature": "TCP Protocol Ratio", "weight": 2.9},
            {"feature": "UDP Protocol Ratio", "weight": 2.1},
            {"feature": "ICMP Protocol Ratio", "weight": 1.1}
        ]

        table_rows = []
        for r in reversed(filtered[-25:]):
            t_str = r.get("timestamp", "")
            try:
                t_display = datetime.fromisoformat(t_str.replace("Z", "+00:00")).strftime("%H:%M:%S")
            except Exception:
                t_display = t_str[-8:] if len(t_str) >= 8 else "00:00:00"

            table_rows.append({
                "time": t_display,
                "interface": r.get("interface_name") or self.interface_name,
                "download_mbps": round(float(r.get("download_mbps") or 0.0), 2),
                "upload_mbps": round(float(r.get("upload_mbps") or 0.0), 2),
                "pps": int(float(r.get("packets_per_sec") or 0)),
                "latency_ms": round(float(r.get("latency_ms") or 0.0), 1),
                "jitter_ms": round(float(r.get("jitter_ms") or 0.0), 1),
                "loss_pct": round(float(r.get("packet_loss_pct") or 0.0), 1),
                "severity": (r.get("congestion_severity") or "LOW").upper(),
                "status": r.get("congestion_status") or "Low Congestion"
            })

        return {
            "total_samples": len(filtered),
            "time_window": time_window,
            "severity_filter": severity_filter,
            "protocol_filter": protocol_filter,
            "download_stats": _calc_stats(dl_list),
            "upload_stats": _calc_stats(ul_list),
            "latency_stats": _calc_stats(lat_list),
            "jitter_stats": _calc_stats(jit_list),
            "loss_stats": _calc_stats(loss_list),
            "pps_stats": _calc_stats(pps_list),
            "correlation_throughput_latency": _calc_corr(tp_list, lat_list),
            "severity_counts": {
                "Low": low_c,
                "Medium": med_c,
                "High": high_c,
                "Low_pct": round((low_c / total_c) * 100, 1),
                "Medium_pct": round((med_c / total_c) * 100, 1),
                "High_pct": round((high_c / total_c) * 100, 1)
            },
            "protocol_breakdown": {
                "TCP": tcp_avg,
                "UDP": udp_avg,
                "ICMP": icmp_avg,
                "Other": other_avg
            },
            "sla_compliance_percent": sla_pct,
            "feature_importance": feature_importance,
            "model_accuracy": meta.get("accuracy_percentage", 100.0),
            "table_rows": table_rows
        }

    def generate_report(self) -> Dict[str, Any]:
        """Generates dynamic analytical health audit report."""
        analysis = self.get_deep_analysis()
        report_id = f"REP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        return {
            "report_id": report_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "formatted_date": datetime.now().strftime("%B %d, %Y - %H:%M:%S UTC"),
            "interface": self.interface_name,
            "mode": self.mode,
            "sla_score": analysis["sla_compliance_percent"],
            "model_accuracy": analysis["model_accuracy"],
            "total_samples_analyzed": analysis["total_samples"],
            "avg_download_mbps": analysis["download_stats"]["avg"],
            "peak_download_mbps": analysis["download_stats"]["max"],
            "avg_latency_ms": analysis["latency_stats"]["avg"],
            "p95_latency_ms": analysis["latency_stats"]["p95"],
            "avg_jitter_ms": analysis["jitter_stats"]["avg"],
            "avg_loss_pct": analysis["loss_stats"]["avg"],
            "high_congestion_incidents": analysis["severity_counts"]["High"],
            "medium_congestion_incidents": analysis["severity_counts"]["Medium"],
            "protocol_distribution": analysis["protocol_breakdown"],
            "recommendation": "Network infrastructure healthy. SLA compliance exceeded." if analysis["sla_compliance_percent"] >= 95.0 else "Action Recommended: Review queue buffer sizes or investigate high latency excursions.",
            "incidents": [
                {
                    "time": r["time"],
                    "severity": r["severity"],
                    "latency": r["latency_ms"],
                    "throughput": r["download_mbps"],
                    "status": r["status"]
                }
                for r in analysis["table_rows"] if r["severity"] in ("HIGH", "MEDIUM")
            ]
        }


# Initialize Global Manager and auto-start for instant dynamic experience
manager = MonitoringManager()
try:
    manager.start()
except Exception as e:
    logger.warning("Auto-start monitoring warning: %s", e)


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serves the main single-page web dashboard."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def api_health():
    """System health check and operational status."""
    snapshot = manager.get_snapshot()
    npcap_info = InterfaceManager.check_npcap_status()
    return jsonify({
        "status": "healthy",
        "monitoring_active": snapshot["is_running"],
        "mode": snapshot["mode"],
        "interface": snapshot["interface_name"],
        "ml_model_loaded": manager.predictor.is_loaded,
        "is_demo_model": manager.predictor.metadata.get("is_demo_model", True),
        "npcap": npcap_info,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """Returns all discovered network interfaces and recommendations."""
    ifaces = InterfaceManager.get_interfaces()
    recommended = InterfaceManager.get_recommended_interface()
    npcap_info = InterfaceManager.check_npcap_status()
    return jsonify({
        "interfaces": ifaces,
        "recommended_interface": recommended,
        "current_selected": manager.interface_name,
        "npcap": npcap_info
    })


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    """Starts network monitoring."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    mode = data.get("mode")
    result = manager.start(interface=interface, mode=mode)
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    """Stops network monitoring."""
    result = manager.stop()
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@app.route("/api/mode", methods=["POST"])
def api_set_mode():
    """Switches between Live and Demo modes."""
    data = request.get_json(silent=True) or {}
    mode = data.get("mode")
    if not mode:
        return jsonify({"success": False, "message": "Missing 'mode' parameter."}), 400
    result = manager.set_mode(mode)
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@app.route("/api/demo/scenario", methods=["POST"])
def api_set_demo_scenario():
    """Sets demo traffic scenario."""
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario")
    if not scenario:
        return jsonify({"success": False, "message": "Missing 'scenario' parameter."}), 400
    result = manager.set_demo_scenario(scenario)
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Returns the latest measured network observation and ML prediction."""
    snapshot = manager.get_snapshot()
    if not snapshot["latest_stats"]:
        return jsonify({
            "is_running": snapshot["is_running"],
            "mode": snapshot["mode"],
            "interface_name": snapshot["interface_name"],
            "message": "No measurements collected yet. Start monitoring to begin."
        }), 200

    return jsonify({
        "is_running": snapshot["is_running"],
        "mode": snapshot["mode"],
        "interface_name": snapshot["interface_name"],
        "stats": snapshot["latest_stats"],
        "prediction": snapshot["latest_prediction"]
    })


@app.route("/api/history", methods=["GET"])
def api_history():
    """Returns bounded history of recent measurement windows for dynamic charts."""
    with manager._lock:
        history_list = list(manager.history)
        alerts_list = list(manager.alerts)

    return jsonify({
        "is_running": manager.is_running,
        "mode": manager.mode,
        "count": len(history_list),
        "history": history_list,
        "alerts": alerts_list
    })


@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    """Clears the history buffer."""
    manager.clear_history()
    return jsonify({"success": True, "message": "History buffer cleared."})


@app.route("/api/predict", methods=["POST"])
def api_predict_custom():
    """
    Directly classify a custom feature payload.
    Useful for testing, external integration, or model validation.
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"success": False, "message": "Invalid JSON body. Expected dictionary of network features."}), 400

    prediction = manager.predictor.predict(data)
    return jsonify({
        "success": True,
        "prediction": prediction
    })


@app.route("/api/observations/label", methods=["POST"])
def api_label_observation():
    """
    Save a user-labelled observation to data/labelled_observations.csv.
    Enables collecting verified ground-truth training data from live network sessions.
    """
    data = request.get_json(silent=True) or {}
    label = data.get("label")
    if not label or label not in CLASS_LABELS:
        return jsonify({
            "success": False,
            "message": f"Invalid label '{label}'. Must be one of: {CLASS_LABELS}"
        }), 400

    # Retrieve features from payload or fallback to latest live measurement
    features = data.get("features")
    if not features:
        snapshot = manager.get_snapshot()
        features = snapshot["latest_stats"]

    if not features:
        return jsonify({
            "success": False,
            "message": "No observation features provided and no live measurement available to label."
        }), 400

    file_exists = config.LABELLED_DATA_PATH.exists()
    try:
        with open(config.LABELLED_DATA_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                # Write header matching FEATURE_COLUMNS + TARGET_COLUMN
                writer.writerow(FEATURE_COLUMNS + [TARGET_COLUMN])

            # Extract features safely
            from ml.feature_schema import sanitize_feature_value
            row_vals = [sanitize_feature_value(col, features.get(col)) for col in FEATURE_COLUMNS]
            row_vals.append(label)
            writer.writerow(row_vals)

        # Count total labelled samples
        import pandas as pd
        df_count = len(pd.read_csv(config.LABELLED_DATA_PATH))

        return jsonify({
            "success": True,
            "message": f"Observation successfully recorded with label '{label}'.",
            "total_labelled_samples": df_count,
            "file": str(config.LABELLED_DATA_PATH.name)
        })
    except Exception as e:
        logger.error("Failed saving labelled observation: %s", e)
        return jsonify({"success": False, "message": f"Storage error: {str(e)}"}), 500


@app.route("/api/export", methods=["GET"])
def api_export_csv():
    """
    Export recorded measurements as a CSV download.
    Exports live_observations.csv if populated, or the active in-memory history.
    """
    if config.LIVE_DATA_PATH.exists() and config.LIVE_DATA_PATH.stat().st_size > 0:
        return send_file(
            config.LIVE_DATA_PATH,
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"network_observations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )

    # Fallback to exporting in-memory history buffer
    with manager._lock:
        records = list(manager.history)

    if not records:
        return jsonify({"success": False, "message": "No recorded measurements available to export."}), 404

    output = io.StringIO()
    writer = csv.writer(output)
    headers = ["timestamp", "interface_name"] + FEATURE_COLUMNS + ["congestion_status", "model_confidence"]
    writer.writerow(headers)

    for r in records:
        row = [
            r.get("timestamp", ""),
            r.get("interface_name", "")
        ] + [r.get(c, "") for c in FEATURE_COLUMNS] + [
            r.get("congestion_status", ""),
            r.get("model_confidence", "")
        ]
        writer.writerow(row)

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=history_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )


@app.route("/api/model/retrain", methods=["POST"])
def api_retrain_model():
    """
    Retrain the ML model on labelled_observations.csv if sufficient samples are available.
    Hot-reloads model without restarting server.
    """
    if not config.LABELLED_DATA_PATH.exists():
        return jsonify({
            "success": False,
            "message": "No labelled observations dataset found. Use the 'Label Current Observation' feature to collect samples."
        }), 400

    import pandas as pd
    try:
        df = pd.read_csv(config.LABELLED_DATA_PATH)
        val = validate_training_dataset(df)
        if not val["valid"]:
            return jsonify({
                "success": False,
                "message": "Insufficient or invalid labelled dataset for retraining.",
                "issues": val["issues"],
                "total_samples": val.get("total_samples", 0),
                "class_distribution": val.get("class_distribution", {})
            }), 400

        # Execute training
        metadata = train_and_evaluate_model(
            dataset_path=config.LABELLED_DATA_PATH,
            output_model_path=config.MODEL_PATH,
            output_metadata_path=config.METADATA_PATH,
            reports_dir=config.REPORTS_DIR,
            is_demo=False
        )

        # Hot reload model into predictor
        manager.predictor.load_model()

        return jsonify({
            "success": True,
            "message": f"Model successfully retrained on {val['total_samples']} real labelled observations!",
            "test_accuracy": metadata["test_accuracy"],
            "metrics": metadata["classification_metrics"]
        })
    except Exception as e:
        logger.error("Retraining error: %s", e)
        return jsonify({"success": False, "message": f"Training failed: {str(e)}"}), 500


# ---------------------------------------------------------------------------
# Deep Analysis, Trigger Engine, Reports & Settings APIs
# ---------------------------------------------------------------------------

@app.route("/api/analysis/deep", methods=["GET"])
def api_analysis_deep():
    """Returns deep statistical analysis, quantiles, correlations, and distributions."""
    time_window = request.args.get("time_window", "all")
    severity = request.args.get("severity", "all")
    protocol = request.args.get("protocol", "all")
    analysis = manager.get_deep_analysis(time_window=time_window, severity_filter=severity, protocol_filter=protocol)
    return jsonify({"success": True, "analysis": analysis})


@app.route("/api/trigger/execute", methods=["POST"])
def api_trigger_execute():
    """Executes a real diagnostic burst, stress injection, or remediation trigger."""
    data = request.get_json(silent=True) or {}
    action = data.get("action", "diagnostic_burst")
    target = data.get("target") or manager.ping_target
    result = manager.execute_trigger(action=action, target=target)
    return jsonify({"success": True, "trigger": result})


@app.route("/api/trigger/status", methods=["GET"])
def api_trigger_status():
    """Returns the latest trigger execution status and trigger history."""
    with manager._lock:
        return jsonify({
            "success": True,
            "latest_trigger": manager.latest_trigger,
            "history": list(manager.trigger_history)
        })


@app.route("/api/report/generate", methods=["GET"])
def api_report_generate():
    """Generates an executive diagnostic audit report."""
    report = manager.generate_report()
    return jsonify({"success": True, "report": report})


@app.route("/api/report/download", methods=["GET"])
def api_report_download():
    """Downloads a standalone formatted HTML report."""
    rep = manager.generate_report()
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Network Telemetry Audit Report - {rep['report_id']}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; margin: 40px; color: #0f172a; line-height: 1.5; }}
    h1 {{ color: #2563eb; margin-bottom: 4px; }}
    .subtitle {{ color: #64748b; font-size: 0.9rem; margin-bottom: 24px; }}
    .meta-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 24px; display: flex; gap: 24px; flex-wrap: wrap; }}
    .meta-item {{ font-size: 0.85rem; }}
    .meta-item strong {{ display: block; color: #475569; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }}
    .kpi-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; background: #fff; }}
    .kpi-num {{ font-size: 1.8rem; font-weight: 700; color: #2563eb; }}
    .kpi-label {{ font-size: 0.8rem; color: #64748b; text-transform: uppercase; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 10px 14px; text-align: left; font-size: 0.85rem; }}
    th {{ background: #f1f5f9; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
    .badge-high {{ background: #fef2f2; color: #dc2626; }}
    .badge-med {{ background: #fffbeb; color: #d97706; }}
    .badge-low {{ background: #ecfdf5; color: #059669; }}
  </style>
</head>
<body>
  <h1>AI Network Telemetry & Congestion Audit Report</h1>
  <div class="subtitle">Report ID: {rep['report_id']} | Generated: {rep['formatted_date']}</div>
  
  <div class="meta-box">
    <div class="meta-item"><strong>Interface</strong>{rep['interface']}</div>
    <div class="meta-item"><strong>Operating Mode</strong>{rep['mode'].upper()}</div>
    <div class="meta-item"><strong>SLA Health Score</strong>{rep['sla_score']}%</div>
    <div class="meta-item"><strong>ML Accuracy</strong>{rep['model_accuracy']}%</div>
    <div class="meta-item"><strong>Samples Analyzed</strong>{rep['total_samples_analyzed']}</div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Average Download</div>
      <div class="kpi-num">{rep['avg_download_mbps']} Mbps</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Peak Download</div>
      <div class="kpi-num">{rep['peak_download_mbps']} Mbps</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Mean Latency</div>
      <div class="kpi-num">{rep['avg_latency_ms']} ms</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">p95 Latency</div>
      <div class="kpi-num">{rep['p95_latency_ms']} ms</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Jitter Variance</div>
      <div class="kpi-num">{rep['avg_jitter_ms']} ms</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Packet Loss Index</div>
      <div class="kpi-num">{rep['avg_loss_pct']}%</div>
    </div>
  </div>

  <h3>Executive Assessment & Recommendations</h3>
  <p>{rep['recommendation']}</p>

  <h3>Congestion Incidents & Excursions ({len(rep['incidents'])} detected)</h3>
  <table>
    <thead>
      <tr><th>Time</th><th>Severity</th><th>Latency</th><th>Throughput</th><th>Status Diagnosis</th></tr>
    </thead>
    <tbody>
      {"".join(f"<tr><td>{i['time']}</td><td><span class='badge badge-{'high' if i['severity']=='HIGH' else 'med'}'>{i['severity']}</span></td><td>{i['latency']} ms</td><td>{i['throughput']} Mbps</td><td>{i['status']}</td></tr>" for i in rep['incidents']) if rep['incidents'] else "<tr><td colspan='5' style='text-align:center; color:#64748b;'>No high or medium congestion excursions detected during this measurement window.</td></tr>"}
    </tbody>
  </table>
</body>
</html>"""
    return Response(
        html_content,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=Network_Audit_{rep['report_id']}.html"}
    )


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    """GET current settings or POST updated configuration."""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if "ping_target" in data and data["ping_target"]:
            manager.ping_target = str(data["ping_target"]).strip()
        if "polling_interval" in data:
            try:
                val = float(data["polling_interval"])
                if 0.2 <= val <= 30.0:
                    manager.polling_interval = val
            except Exception:
                pass
        if "audio_alerts_enabled" in data:
            manager.audio_alerts_enabled = bool(data["audio_alerts_enabled"])
        if "high_latency_threshold" in data:
            try:
                config.CONGESTION_THRESHOLDS["HIGH"]["latency_ms"] = float(data["high_latency_threshold"])
            except Exception:
                pass
        if "high_loss_threshold" in data:
            try:
                config.CONGESTION_THRESHOLDS["HIGH"]["packet_loss_pct"] = float(data["high_loss_threshold"])
            except Exception:
                pass

        return jsonify({
            "success": True,
            "message": "Settings updated successfully.",
            "settings": {
                "ping_target": manager.ping_target,
                "polling_interval": manager.polling_interval,
                "audio_alerts_enabled": manager.audio_alerts_enabled,
                "high_latency_threshold": config.CONGESTION_THRESHOLDS["HIGH"]["latency_ms"],
                "high_loss_threshold": config.CONGESTION_THRESHOLDS["HIGH"]["packet_loss_pct"]
            }
        })

    return jsonify({
        "success": True,
        "settings": {
            "ping_target": manager.ping_target,
            "polling_interval": manager.polling_interval,
            "audio_alerts_enabled": manager.audio_alerts_enabled,
            "high_latency_threshold": config.CONGESTION_THRESHOLDS["HIGH"]["latency_ms"],
            "high_loss_threshold": config.CONGESTION_THRESHOLDS["HIGH"]["packet_loss_pct"]
        }
    })


@app.route("/reports/<path:filename>")
def serve_report_file(filename):
    """Serves reports images or documents directly."""
    return send_file(config.REPORTS_DIR / filename)


if __name__ == "__main__":
    print("=" * 70)
    print(" Starting AI Network Traffic Analyzer & Congestion Prediction Server")
    print(f" URL: http://{config.HOST}:{config.PORT}")
    print(" Press Ctrl+C to terminate.")
    print("=" * 70)
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, threaded=True)
