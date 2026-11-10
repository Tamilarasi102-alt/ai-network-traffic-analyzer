# Network Telemetry Datasets

This directory manages training data and continuous measurement logs for the AI Network Traffic Analyzer and Congestion Prediction System.

---

## 1. Files in this Directory

| File Name | Purpose | Data Source |
|---|---|---|
| `demo_training_data.csv` | Synthetic bootstrap training set generated via network queuing models | Simulated bootstrap (`train_model.py`) |
| `live_observations.csv` | Continual telemetry logs recorded during active Live Mode monitoring | Real OS network drivers & Scapy |
| `labelled_observations.csv` | User-verified ground-truth observations labelled as Low/Medium/High | Curated via UI "Save Observation" |

---

## 2. Telemetry Feature Schema

Every row adheres strictly to the 12-dimensional canonical schema defined in `ml/feature_schema.py`:

| Feature Name | Unit / Range | Description |
|---|---|---|
| `download_mbps` | Mbps ($\ge 0$) | Real-time downstream throughput computed from OS kernel deltas |
| `upload_mbps` | Mbps ($\ge 0$) | Real-time upstream throughput computed from OS kernel deltas |
| `packets_per_sec` | PPS ($\ge 0$) | Total packets received and transmitted per measurement second |
| `avg_packet_size` | Bytes | Average frame length ($\text{Bytes} / \text{Packets}$) |
| `bandwidth_util_percent` | % (0 – 100) | Calculated against physical link capacity when reported by driver |
| `latency_ms` | Milliseconds | Active ICMP round-trip latency to configurable target (8.8.8.8) |
| `jitter_ms` | Milliseconds | Statistical variation between consecutive successful latency probes |
| `packet_loss_pct` | % (0 – 100) | Rolling percentage of dropped ping packets over latest 10 probes |
| `tcp_ratio` | 0.0 – 1.0 | Proportion of TCP packets observed in the measurement window |
| `udp_ratio` | 0.0 – 1.0 | Proportion of UDP packets observed in the measurement window |
| `icmp_ratio` | 0.0 – 1.0 | Proportion of ICMP packets observed in the measurement window |
| `unique_flows` | Count ($\ge 0$) | Count of active 5-tuple conversations (`src_ip`, `dst_ip`, `sport`, `dport`, `proto`) |
| `congestion_level` | Target Class | Ground-truth label: `Low Congestion`, `Medium Congestion`, `High Congestion` |

---

## 3. Ground-Truth Data Curation & Model Retraining

1. Launch the web dashboard and switch to **Live Mode**.
2. Click **Start Monitoring** on your active network adapter (e.g., Wi-Fi).
3. Observe actual network performance during different real-world conditions (idle web browsing, 4K streaming, multi-file torrents/downloads).
4. Use the **Ground-Truth Data Labelling** tool at the bottom of the Congestion Assessment panel:
   - Select the verified condition (`Low Congestion`, `Medium Congestion`, or `High Congestion`).
   - Click **Save Observation**.
5. Once at least 15–20 representative observations are saved across classes, click **Retrain on Labelled Data** (or execute `python train_model.py --dataset data/labelled_observations.csv`).
6. The Random Forest model hot-reloads dynamically into memory with zero server downtime.
