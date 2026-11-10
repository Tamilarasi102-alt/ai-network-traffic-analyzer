/**
 * AI Network Traffic Analyzer & Congestion Prediction
 * Frontend Controller & Dynamic Multi-View Visualizer
 */

// Application State
const state = {
  mode: "demo",           // "demo" | "live"
  isMonitoring: false,
  selectedInterface: "",
  pollIntervalMs: 1000,   // Real-time dynamic 1.0s interval
  pollTimer: null,
  historyMaxPoints: 30,
  latestStats: null,
  latestPrediction: null,
  currentTab: "dashboard",
  analysisTimeFilter: "all",
  allAnalysisRecords: [],
  audioContext: null
};

// Chart Instances
let throughputChart = null;
let ppsChart = null;
let latencyChart = null;
let protocolChart = null;
let congestionChart = null;

// Deep Analysis Chart Instances
let analysisScatterChart = null;
let analysisQuantileChart = null;
let analysisFeatureChart = null;
let analysisSeverityChart = null;

// DOM Elements cache
const elements = {};

document.addEventListener("DOMContentLoaded", () => {
  cacheDOMElements();
  initCharts();
  loadInterfaces();
  checkInitialHealth();
  startPollingLoop();
});

/**
 * Cache frequently accessed DOM nodes.
 */
function cacheDOMElements() {
  elements.interfaceSelect = document.getElementById("interfaceSelect");
  elements.modePill = document.getElementById("modePill");
  elements.modePillText = document.getElementById("modePillText");
  elements.monitorPill = document.getElementById("monitorPill");
  elements.monitorPillText = document.getElementById("monitorPillText");
  elements.scapyPill = document.getElementById("scapyPill");
  elements.scapyPillText = document.getElementById("scapyPillText");

  elements.degradedBanner = document.getElementById("degradedBanner");
  elements.bannerMessage = document.getElementById("bannerMessage");
  elements.demoScenarioGroup = document.getElementById("demoScenarioGroup");
  elements.demoScenarioSelect = document.getElementById("demoScenarioSelect");

  elements.btnStart = document.getElementById("btnStart");
  elements.btnStop = document.getElementById("btnStop");
  elements.btnLiveMode = document.getElementById("btnLiveMode");
  elements.btnDemoMode = document.getElementById("btnDemoMode");

  // Telemetry Cards
  elements.statDownload = document.getElementById("statDownload");
  elements.statUpload = document.getElementById("statUpload");
  elements.statBytesRecv = document.getElementById("statBytesRecv");
  elements.statBytesSent = document.getElementById("statBytesSent");
  elements.statPPS = document.getElementById("statPPS");
  elements.statRecvPPS = document.getElementById("statRecvPPS");
  elements.statSentPPS = document.getElementById("statSentPPS");
  elements.statAvgPktSize = document.getElementById("statAvgPktSize");
  elements.statBandwidthUtil = document.getElementById("statBandwidthUtil");
  elements.statLinkSpeed = document.getElementById("statLinkSpeed");
  elements.statLatency = document.getElementById("statLatency");
  elements.statPingTarget = document.getElementById("statPingTarget");
  elements.statJitter = document.getElementById("statJitter");
  elements.statLoss = document.getElementById("statLoss");
  elements.statFlows = document.getElementById("statFlows");

  // Congestion Panel
  elements.congestionStatusBadge = document.getElementById("congestionStatusBadge");
  elements.congestionStatusText = document.getElementById("congestionStatusText");
  elements.predSource = document.getElementById("predSource");
  elements.predModelName = document.getElementById("predModelName");
  elements.predConfidence = document.getElementById("predConfidence");
  elements.confidenceBar = document.getElementById("confidenceBar");

  elements.probBarLow = document.getElementById("probBarLow");
  elements.probValLow = document.getElementById("probValLow");
  elements.probBarMed = document.getElementById("probBarMed");
  elements.probValMed = document.getElementById("probValMed");
  elements.probBarHigh = document.getElementById("probBarHigh");
  elements.probValHigh = document.getElementById("probValHigh");

  elements.predExplanation = document.getElementById("predExplanation");
  elements.predRecommendations = document.getElementById("predRecommendations");
  elements.userLabelSelect = document.getElementById("userLabelSelect");

  elements.alertsContainer = document.getElementById("alertsContainer");
  elements.toastContainer = document.getElementById("toastContainer");
}

// ---------------------------------------------------------------------------
// Multi-View Navigation Tab Controller
// ---------------------------------------------------------------------------

function switchTab(tabName) {
  state.currentTab = tabName;

  // Update nav tabs active state
  const tabs = ["dashboard", "analysis", "trigger", "reports", "settings"];
  tabs.forEach((t) => {
    const tabBtn = document.getElementById(`navTab${t.charAt(0).toUpperCase() + t.slice(1)}`);
    const viewDiv = document.getElementById(`view-${t}`);
    if (tabBtn) {
      if (t === tabName) {
        tabBtn.classList.add("active");
      } else {
        tabBtn.classList.remove("active");
      }
    }
    if (viewDiv) {
      if (t === tabName) {
        viewDiv.classList.remove("hidden");
        viewDiv.classList.add("active");
      } else {
        viewDiv.classList.add("hidden");
        viewDiv.classList.remove("active");
      }
    }
  });

  // Action hook on tab activation
  if (tabName === "analysis") {
    loadDeepAnalysis();
  } else if (tabName === "trigger") {
    refreshTriggerStatus();
  } else if (tabName === "reports") {
    generateLiveReport();
  } else if (tabName === "settings") {
    loadSettings();
  }
}

function openAnalysisView() {
  switchTab("analysis");
}

// ---------------------------------------------------------------------------
// Chart Initialization & Dashboard Streaming
// ---------------------------------------------------------------------------

function initCharts() {
  const chartOptionsBase = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      legend: {
        position: "top",
        labels: { boxWidth: 12, font: { size: 11, weight: "500" }, color: "#475569" }
      },
      tooltip: {
        mode: "index",
        intersect: false,
        padding: 8,
        titleFont: { size: 12 },
        bodyFont: { size: 12 }
      }
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { font: { size: 10 }, maxRotation: 0, color: "#94a3b8" }
      },
      y: {
        grid: { color: "#f1f5f9" },
        ticks: { font: { size: 10 }, color: "#94a3b8" },
        beginAtZero: true
      }
    }
  };

  // 1. Throughput Chart
  const ctxThroughput = document.getElementById("throughputChart").getContext("2d");
  throughputChart = new Chart(ctxThroughput, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Download (Mbps)",
          borderColor: "#2563eb",
          backgroundColor: "rgba(37, 99, 235, 0.08)",
          fill: true,
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 2,
          data: []
        },
        {
          label: "Upload (Mbps)",
          borderColor: "#059669",
          backgroundColor: "rgba(5, 150, 105, 0.05)",
          fill: true,
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 2,
          data: []
        }
      ]
    },
    options: chartOptionsBase
  });

  // 2. PPS Chart
  const ctxPps = document.getElementById("ppsChart").getContext("2d");
  ppsChart = new Chart(ctxPps, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Packets / Sec",
          borderColor: "#7c3aed",
          backgroundColor: "rgba(124, 58, 237, 0.08)",
          fill: true,
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 2,
          data: []
        }
      ]
    },
    options: chartOptionsBase
  });

  // 3. Latency & Jitter Chart
  const ctxLatency = document.getElementById("latencyChart").getContext("2d");
  latencyChart = new Chart(ctxLatency, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Latency (ms)",
          borderColor: "#f59e0b",
          tension: 0.2,
          borderWidth: 2,
          pointRadius: 2,
          data: []
        },
        {
          label: "Jitter (ms)",
          borderColor: "#06b6d4",
          tension: 0.2,
          borderWidth: 2,
          pointRadius: 2,
          data: []
        }
      ]
    },
    options: chartOptionsBase
  });

  // 4. Transport Protocol Doughnut Chart
  const ctxProto = document.getElementById("protocolChart").getContext("2d");
  protocolChart = new Chart(ctxProto, {
    type: "doughnut",
    data: {
      labels: ["TCP", "UDP", "ICMP", "Other"],
      datasets: [
        {
          data: [75, 20, 5, 0],
          backgroundColor: ["#3b82f6", "#f97316", "#10b981", "#cbd5e1"],
          borderWidth: 2,
          borderColor: "#ffffff"
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: { boxWidth: 12, font: { size: 11, weight: "500" }, color: "#475569" }
        }
      },
      cutout: "68%"
    }
  });

  // 5. Congestion History Step-Line Chart
  const ctxCongestion = document.getElementById("congestionHistoryChart").getContext("2d");
  congestionChart = new Chart(ctxCongestion, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Congestion Severity",
          stepped: true,
          borderColor: "#2563eb",
          backgroundColor: "rgba(37, 99, 235, 0.06)",
          fill: true,
          borderWidth: 2,
          pointRadius: 4,
          pointBackgroundColor: [],
          data: []
        }
      ]
    },
    options: {
      ...chartOptionsBase,
      scales: {
        ...chartOptionsBase.scales,
        y: {
          min: 0.5,
          max: 3.5,
          ticks: {
            stepSize: 1,
            callback: (val) => {
              if (val === 1) return "LOW";
              if (val === 2) return "MEDIUM";
              if (val === 3) return "HIGH";
              return "";
            },
            font: { weight: "600" }
          }
        }
      }
    }
  });
}

/**
 * Fetch initial health and server status.
 */
async function checkInitialHealth() {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) return;
    const data = await res.json();
    setModeUI(data.mode);
    setMonitoringUI(data.monitoring_active);
    if (data.interface) {
      state.selectedInterface = data.interface;
      if (elements.interfaceSelect) {
        elements.interfaceSelect.value = data.interface;
      }
    }
    // Auto-engage monitoring stream if not already active
    if (!data.monitoring_active) {
      startMonitoring();
    }
  } catch (err) {
    console.error("Health check error:", err);
  }
}

/**
 * Fetch discovered interfaces from psutil.
 */
async function loadInterfaces() {
  try {
    const res = await fetch("/api/interfaces");
    if (!res.ok) throw new Error("Failed to load network interfaces");
    const data = await res.json();

    if (elements.interfaceSelect) {
      elements.interfaceSelect.innerHTML = "";
      data.interfaces.forEach((iface) => {
        const opt = document.createElement("option");
        opt.value = iface.name;
        opt.textContent = iface.display_name;
        if (iface.name === data.recommended_interface) {
          opt.selected = true;
        }
        elements.interfaceSelect.appendChild(opt);
      });
      state.selectedInterface = elements.interfaceSelect.value;
    } else {
      state.selectedInterface = data.recommended_interface || (data.interfaces[0] ? data.interfaces[0].name : "Wi-Fi");
    }
  } catch (err) {
    console.error("Failed loading interfaces:", err);
  }
}

/**
 * Start periodic statistics polling loop.
 */
function startPollingLoop() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(pollStatsNow, state.pollIntervalMs);
  pollStatsNow();
}

/**
 * Poll current telemetry observation and history buffer.
 */
async function pollStatsNow() {
  try {
    const [statsRes, historyRes] = await Promise.all([
      fetch("/api/stats"),
      fetch("/api/history")
    ]);

    if (statsRes.ok) {
      const statsData = await statsRes.json();
      if (statsData.stats) {
        updateTelemetryCards(statsData.stats);
        if (statsData.prediction) {
          updateCongestionPanel(statsData.prediction);
        }
      }
      setMonitoringUI(statsData.is_running);
      setModeUI(statsData.mode);
    }

    if (historyRes.ok) {
      const histData = await historyRes.json();
      if (histData.history && histData.history.length > 0) {
        updateCharts(histData.history);
      }
      if (histData.alerts) {
        updateAlerts(histData.alerts);
      }
    }
  } catch (err) {
    console.warn("Poll fetch error:", err);
  }
}

/**
 * Update the 9 primary Telemetry Stat Cards.
 */
function updateTelemetryCards(stats) {
  state.latestStats = stats;

  // Throughput
  elements.statDownload.textContent = formatNumber(stats.download_mbps, 2);
  elements.statUpload.textContent = formatNumber(stats.upload_mbps, 2);
  elements.statBytesRecv.textContent = formatBytesPerSec(stats.bytes_recv_per_sec);
  elements.statBytesSent.textContent = formatBytesPerSec(stats.bytes_sent_per_sec);

  // PPS
  elements.statPPS.textContent = formatNumber(stats.packets_per_sec, 0);
  elements.statRecvPPS.textContent = formatNumber(stats.packets_recv_per_sec, 0);
  elements.statSentPPS.textContent = formatNumber(stats.packets_sent_per_sec, 0);

  // Frame size
  elements.statAvgPktSize.textContent = stats.avg_packet_size !== null ? formatNumber(stats.avg_packet_size, 0) : "N/A";

  // Bandwidth utilization
  if (stats.bandwidth_util_percent !== null) {
    elements.statBandwidthUtil.textContent = formatNumber(stats.bandwidth_util_percent, 1);
  } else {
    elements.statBandwidthUtil.textContent = "N/A";
  }

  // Link speed
  if (stats.interface_speed_mbps) {
    elements.statLinkSpeed.textContent = `${stats.interface_speed_mbps} Mbps`;
  } else {
    elements.statLinkSpeed.textContent = "Unknown";
  }

  // Latency & Jitter
  elements.statLatency.textContent = stats.latency_ms !== null ? formatNumber(stats.latency_ms, 1) : "N/A";
  elements.statJitter.textContent = stats.jitter_ms !== null ? formatNumber(stats.jitter_ms, 1) : "N/A";
  elements.statLoss.textContent = stats.packet_loss_pct !== null ? `${formatNumber(stats.packet_loss_pct, 1)}` : "0.0";
  elements.statPingTarget.textContent = stats.ping_target || "8.8.8.8";

  // Unique Flows
  elements.statFlows.textContent = stats.unique_flows !== null ? formatNumber(stats.unique_flows, 0) : "N/A";

  // Dynamic visual feedback pulse
  [elements.statDownload, elements.statUpload, elements.statPPS, elements.statLatency].forEach((el) => {
    if (el) {
      el.classList.add("value-pulse");
      setTimeout(() => el.classList.remove("value-pulse"), 300);
    }
  });

  // Dynamic Latency Quality & Accuracy Engine
  updateDynamicLatencyIntelligence(stats);

  // Scapy Status Pill
  if (stats.scapy_status) {
    elements.scapyPillText.textContent = `SCAPY: ${stats.scapy_status.toUpperCase()}`;
    if (stats.scapy_degraded) {
      elements.scapyPill.className = "status-pill pill-demo";
      if (stats.capture_mode === "live") {
        elements.degradedBanner.classList.remove("hidden");
        elements.bannerMessage.textContent = stats.scapy_message || "Packet capture restricted by Windows Npcap admin settings.";
      }
    } else {
      elements.scapyPill.className = "status-pill pill-running";
      elements.degradedBanner.classList.add("hidden");
    }
  }
}

/**
 * Updates the Dynamic Latency Quality Ring, AI weights, and Grade.
 */
function updateDynamicLatencyIntelligence(stats) {
  const elScore = document.getElementById("dynamicLatencyScore");
  const elRing = document.getElementById("latencyScoreRing");
  const elGrade = document.getElementById("dynamicLatencyGrade");
  const elLat = document.getElementById("dynLatVal");
  const elJit = document.getElementById("dynJitVal");
  const elLoss = document.getElementById("dynLossVal");

  if (!elScore) return;

  const lat = stats.latency_ms !== null && stats.latency_ms !== undefined ? Number(stats.latency_ms) : 25.0;
  const jit = stats.jitter_ms !== null && stats.jitter_ms !== undefined ? Number(stats.jitter_ms) : 1.5;
  const loss = stats.packet_loss_pct !== null && stats.packet_loss_pct !== undefined ? Number(stats.packet_loss_pct) : 0.0;

  if (elLat) elLat.textContent = `${lat.toFixed(1)} ms`;
  if (elJit) elJit.textContent = `${jit.toFixed(1)} ms`;
  if (elLoss) elLoss.textContent = `${loss.toFixed(1)}%`;

  // Compute Latency Quality Score (100 - penalties)
  const latPenalty = Math.min(50, Math.max(0, (lat - 20) * 0.35));
  const jitPenalty = Math.min(25, jit * 2.5);
  const lossPenalty = Math.min(30, loss * 3.0);
  const score = Math.max(5, Math.min(100, Math.round(100 - (latPenalty + jitPenalty + lossPenalty))));

  elScore.textContent = `${score}%`;

  // Progress ring circumference: 2 * PI * 50 ~= 314.159
  if (elRing) {
    const circumference = 314.159;
    const offset = circumference - (score / 100) * circumference;
    elRing.style.strokeDashoffset = offset;

    if (score >= 85) {
      elRing.style.stroke = "#10b981";
      if (elGrade) {
        elGrade.className = "status-pill-quality pill-optimal";
        elGrade.textContent = "OPTIMAL HEALTH";
      }
    } else if (score >= 60) {
      elRing.style.stroke = "#f59e0b";
      if (elGrade) {
        elGrade.className = "status-pill-quality pill-fair";
        elGrade.textContent = "MODERATE JITTER";
      }
    } else {
      elRing.style.stroke = "#ef4444";
      if (elGrade) {
        elGrade.className = "status-pill-quality pill-degraded";
        elGrade.textContent = "HIGH DELAY SATURATION";
      }
    }
  }
}

/**
 * Update Congestion Prediction & Confidence Display.
 */
function updateCongestionPanel(pred) {
  state.latestPrediction = pred;

  const status = pred.status || "Low Congestion";
  elements.congestionStatusText.textContent = status.toUpperCase();
  elements.congestionStatusBadge.className = "congestion-badge " + getBadgeClass(pred.severity);

  // Audio beep if high severity alert enabled
  if (pred.severity === "HIGH") {
    playAlertBeep();
  }

  // Classification Source
  const sourceText = pred.source === "ML_MODEL" 
    ? (pred.is_demo_model ? "ML (Demo-Trained RF)" : "ML (Real-Data Trained RF)")
    : "Rule-Based Baseline";
  elements.predSource.textContent = sourceText;
  elements.predModelName.textContent = pred.model_name || "Classifier";

  // Confidence
  if (pred.confidence !== null && pred.confidence !== undefined) {
    const confPct = Math.round(pred.confidence * 100);
    elements.predConfidence.textContent = `${confPct}%`;
    elements.confidenceBar.style.width = `${confPct}%`;
    const elAiConf = document.getElementById("dynamicAiConfidence");
    if (elAiConf) elAiConf.textContent = `${confPct}%`;
  } else {
    elements.predConfidence.textContent = "N/A (Rule Engine)";
    elements.confidenceBar.style.width = "0%";
    const elAiConf = document.getElementById("dynamicAiConfidence");
    if (elAiConf) elAiConf.textContent = "N/A (Rule Engine)";
  }

  // Probabilities breakdown
  const probs = pred.probabilities;
  if (probs) {
    const pLow = Math.round((probs["Low Congestion"] || 0) * 100);
    const pMed = Math.round((probs["Medium Congestion"] || 0) * 100);
    const pHigh = Math.round((probs["High Congestion"] || 0) * 100);

    elements.probBarLow.style.width = `${pLow}%`;
    elements.probValLow.textContent = `${pLow}%`;

    elements.probBarMed.style.width = `${pMed}%`;
    elements.probValMed.textContent = `${pMed}%`;

    elements.probBarHigh.style.width = `${pHigh}%`;
    elements.probValHigh.textContent = `${pHigh}%`;
  } else {
    elements.probBarLow.style.width = "0%";
    elements.probValLow.textContent = "N/A";
    elements.probBarMed.style.width = "0%";
    elements.probValMed.textContent = "N/A";
    elements.probBarHigh.style.width = "0%";
    elements.probValHigh.textContent = "N/A";
  }

  // Explanation & Recommendations
  elements.predExplanation.textContent = pred.explanation || "No explanation provided.";
  
  elements.predRecommendations.innerHTML = "";
  if (pred.recommendations && pred.recommendations.length > 0) {
    pred.recommendations.forEach((rec) => {
      const li = document.createElement("li");
      li.textContent = rec;
      elements.predRecommendations.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.textContent = "Normal operating conditions. No immediate action necessary.";
    elements.predRecommendations.appendChild(li);
  }
}

/**
 * Update Chart.js instances with history observations.
 */
function updateCharts(history) {
  const recent = history.slice(-state.historyMaxPoints);
  const labels = recent.map((item) => {
    const t = new Date(item.timestamp);
    return isNaN(t.getTime()) ? "" : t.toLocaleTimeString();
  });

  // 1. Throughput
  throughputChart.data.labels = labels;
  throughputChart.data.datasets[0].data = recent.map((d) => d.download_mbps || 0);
  throughputChart.data.datasets[1].data = recent.map((d) => d.upload_mbps || 0);
  throughputChart.update("none");

  // 2. PPS
  ppsChart.data.labels = labels;
  ppsChart.data.datasets[0].data = recent.map((d) => d.packets_per_sec || 0);
  ppsChart.update("none");

  // 3. Latency & Jitter
  latencyChart.data.labels = labels;
  latencyChart.data.datasets[0].data = recent.map((d) => d.latency_ms !== null ? d.latency_ms : 0);
  latencyChart.data.datasets[1].data = recent.map((d) => d.jitter_ms !== null ? d.jitter_ms : 0);
  latencyChart.update("none");

  // 4. Protocol Distribution
  if (recent.length > 0) {
    const last = recent[recent.length - 1];
    const tcp = Math.round((last.tcp_ratio || 0.75) * 100);
    const udp = Math.round((last.udp_ratio || 0.20) * 100);
    const icmp = Math.round((last.icmp_ratio || 0.05) * 100);
    const other = Math.max(0, 100 - (tcp + udp + icmp));
    protocolChart.data.datasets[0].data = [tcp, udp, icmp, other];
    protocolChart.update("none");
  }

  // 5. Congestion History Step Line
  congestionChart.data.labels = labels;
  const severityPoints = recent.map((d) => {
    const sev = (d.congestion_severity || "LOW").toUpperCase();
    if (sev === "HIGH") return 3;
    if (sev === "MEDIUM") return 2;
    return 1;
  });
  const pointColors = recent.map((d) => {
    const sev = (d.congestion_severity || "LOW").toUpperCase();
    if (sev === "HIGH") return "#ef4444";
    if (sev === "MEDIUM") return "#f59e0b";
    return "#10b981";
  });

  congestionChart.data.datasets[0].data = severityPoints;
  congestionChart.data.datasets[0].pointBackgroundColor = pointColors;
  congestionChart.update("none");
}

/**
 * Render system alert log.
 */
function updateAlerts(alerts) {
  if (!alerts || alerts.length === 0) return;
  elements.alertsContainer.innerHTML = "";

  const reversed = [...alerts].reverse().slice(0, 20);
  reversed.forEach((a) => {
    const div = document.createElement("div");
    div.className = `alert-item ${getAlertClass(a.severity)}`;

    div.innerHTML = `
      <span class="alert-time">${a.time_display || "00:00:00"}</span>
      <span class="alert-tag">${a.severity}</span>
      <span class="alert-msg">${escapeHtml(a.message)}</span>
    `;
    elements.alertsContainer.appendChild(div);
  });
}

// ---------------------------------------------------------------------------
// Trigger Engine Logic (Requirement #3)
// ---------------------------------------------------------------------------

async function runTrigger(actionType) {
  const badge = document.getElementById("triggerStatusBadge");
  const navBadge = document.getElementById("navTriggerBadge");
  const consoleEl = document.getElementById("triggerConsole");
  const targetHost = (document.getElementById("triggerTargetHost") && document.getElementById("triggerTargetHost").value.trim()) || "8.8.8.8";

  if (badge) {
    badge.className = "status-pill-quality pill-pending";
    badge.textContent = "TRIGGERING...";
  }
  if (navBadge) {
    navBadge.textContent = "ACTIVE";
    navBadge.style.backgroundColor = "#fffbeb";
    navBadge.style.color = "#b45309";
  }

  appendConsole(`[${new Date().toLocaleTimeString()}] Dispatching trigger '${actionType.toUpperCase()}' targeting ${targetHost}...`);

  try {
    const res = await fetch("/api/trigger/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: actionType, target: targetHost })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      const trig = data.trigger;
      if (badge) {
        badge.className = trig.status === "Triggered" || trig.status === "Active" ? "status-pill-quality pill-optimal" : "status-pill-quality pill-failed";
        badge.textContent = `${trig.status.toUpperCase()} (${trig.execution_time_ms} ms)`;
      }
      if (navBadge) {
        navBadge.textContent = "SUCCESS";
        navBadge.style.backgroundColor = "#ecfdf5";
        navBadge.style.color = "#047857";
      }

      // Append returned execution logs to terminal
      if (trig.logs && Array.isArray(trig.logs)) {
        trig.logs.forEach((logLine) => appendConsole(logLine));
      }

      // Add to Trigger History Table
      appendTriggerHistoryRow(trig);

      showToast(
        "⚡ Trigger Executed Successfully",
        `Action: ${actionType} completed in ${trig.execution_time_ms}ms. ML status: ${trig.prediction ? trig.prediction.status : 'Normal'}.`,
        "success"
      );

      // Re-poll stats to reflect trigger results immediately
      pollStatsNow();
    } else {
      if (badge) {
        badge.className = "status-pill-quality pill-failed";
        badge.textContent = "FAILED";
      }
      appendConsole(`[${new Date().toLocaleTimeString()}] ERROR: Trigger failed: ${data.message || 'Unknown error'}`);
      showToast("Trigger Failed", data.message || "Failed to dispatch trigger.", "danger");
    }
  } catch (err) {
    if (badge) {
      badge.className = "status-pill-quality pill-failed";
      badge.textContent = "NETWORK ERROR";
    }
    appendConsole(`[${new Date().toLocaleTimeString()}] NETWORK EXCEPTION: ${err.message}`);
    showToast("Trigger Error", err.message, "danger");
  }
}

async function handleTrigger() {
  const btn = document.getElementById("btnTrigger");
  const txt = document.getElementById("triggerBtnText");
  if (btn) {
    btn.disabled = true;
    btn.classList.add("trigger-active");
  }
  if (txt) txt.textContent = "⚡ TRIGGERING...";

  try {
    await runTrigger("diagnostic_burst");
  } catch (err) {
    console.warn("Trigger error:", err);
  } finally {
    setTimeout(() => {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("trigger-active");
      }
      if (txt) txt.textContent = "TRIGGER";
    }, 400);
  }
}

function appendConsole(text) {
  const consoleEl = document.getElementById("triggerConsole");
  if (!consoleEl) return;
  consoleEl.textContent += `\n${text}`;
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function clearTriggerConsole() {
  const consoleEl = document.getElementById("triggerConsole");
  if (consoleEl) {
    consoleEl.textContent = `[${new Date().toLocaleTimeString()}] Console reset. Trigger Engine standing by.`;
  }
}

function copyTriggerConsole() {
  const consoleEl = document.getElementById("triggerConsole");
  if (consoleEl) {
    navigator.clipboard.writeText(consoleEl.textContent).then(() => {
      showToast("Copied to Clipboard", "Terminal execution output copied.", "info");
    });
  }
}

function appendTriggerHistoryRow(trig) {
  const tbody = document.getElementById("triggerHistoryTableBody");
  if (!tbody) return;

  // Clear placeholder row
  if (tbody.children.length === 1 && tbody.children[0].children.length === 1) {
    tbody.innerHTML = "";
  }

  const tr = document.createElement("tr");
  const timeDisplay = new Date(trig.timestamp).toLocaleTimeString();
  const rttDisplay = trig.avg_rtt_ms ? `${trig.avg_rtt_ms} ms` : (trig.stats && trig.stats.download_mbps ? `${trig.stats.download_mbps.toFixed(1)} Mbps` : 'N/A');
  const verdict = trig.prediction ? trig.prediction.status : "Low Congestion";

  tr.innerHTML = `
    <td class="font-mono">${trig.trigger_id}</td>
    <td class="font-bold">${trig.action}</td>
    <td><span class="status-pill-quality ${trig.status === 'Failed' ? 'pill-failed' : 'pill-optimal'}">${trig.status}</span></td>
    <td class="font-mono">${trig.target || 'N/A'}</td>
    <td class="font-mono">${trig.execution_time_ms} ms</td>
    <td class="font-mono">${rttDisplay}</td>
    <td><span class="badge ${verdict.includes('High') ? 'badge-high' : (verdict.includes('Medium') ? 'badge-medium' : 'badge-low')}">${verdict}</span></td>
    <td>${timeDisplay}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
}

async function refreshTriggerStatus() {
  try {
    const res = await fetch("/api/trigger/status");
    if (!res.ok) return;
    const data = await res.json();
    if (data.latest_trigger) {
      const badge = document.getElementById("triggerStatusBadge");
      if (badge) {
        badge.textContent = `${data.latest_trigger.status.toUpperCase()} (${data.latest_trigger.execution_time_ms}ms)`;
      }
    }
    if (data.history && data.history.length > 0) {
      const tbody = document.getElementById("triggerHistoryTableBody");
      if (tbody) {
        tbody.innerHTML = "";
        data.history.slice(-10).reverse().forEach(appendTriggerHistoryRow);
      }
    }
  } catch (err) {
    console.warn("Failed refreshing trigger status:", err);
  }
}

// ---------------------------------------------------------------------------
// Deep Analysis Functionality (Requirement #2)
// ---------------------------------------------------------------------------

async function loadDeepAnalysis() {
  const timeWindow = state.analysisTimeFilter;
  const severity = (document.getElementById("analysisSeverityFilter") && document.getElementById("analysisSeverityFilter").value) || "all";
  const protocol = (document.getElementById("analysisProtocolFilter") && document.getElementById("analysisProtocolFilter").value) || "all";

  try {
    const url = `/api/analysis/deep?time_window=${timeWindow}&severity=${severity}&protocol=${protocol}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error("Failed fetching deep analysis");
    const data = await res.json();
    const ana = data.analysis;

    // 1. Populate KPI Metrics
    const elCorr = document.getElementById("anaCorrelation");
    const elCorrVerdict = document.getElementById("anaCorrVerdict");
    const elSla = document.getElementById("anaSlaScore");
    const elP95 = document.getElementById("anaP95Latency");
    const elP50 = document.getElementById("anaP50Latency");
    const elMeanJit = document.getElementById("anaMeanJitter");
    const elMaxJit = document.getElementById("anaMaxJitter");
    const elMaxTp = document.getElementById("anaMaxThroughput");
    const elAvgTp = document.getElementById("anaAvgThroughput");

    if (elCorr) elCorr.textContent = (ana.correlation_throughput_latency > 0 ? "+" : "") + ana.correlation_throughput_latency.toFixed(3);
    if (elCorrVerdict) {
      if (ana.correlation_throughput_latency > 0.5) {
        elCorrVerdict.textContent = "High queue buildup: Delay increases with throughput.";
      } else if (ana.correlation_throughput_latency < -0.3) {
        elCorrVerdict.textContent = "Throughput throttled during latency spikes.";
      } else {
        elCorrVerdict.textContent = "Stable decoupling: Traffic flowing within capacity.";
      }
    }

    if (elSla) elSla.textContent = `${ana.sla_compliance_percent}%`;
    if (elP95) elP95.textContent = `${ana.latency_stats.p95}`;
    if (elP50) elP50.textContent = `${ana.latency_stats.p50} ms`;
    if (elMeanJit) elMeanJit.textContent = `${ana.jitter_stats.avg}`;
    if (elMaxJit) elMaxJit.textContent = `${ana.jitter_stats.max} ms`;
    if (elMaxTp) elMaxTp.textContent = `${ana.download_stats.max}`;
    if (elAvgTp) elAvgTp.textContent = `${ana.download_stats.avg} Mbps`;

    // 2. Render In-Depth Analytical Charts
    renderAnalysisCharts(ana);

    // 3. Populate Interactive Table
    state.allAnalysisRecords = ana.table_rows || [];
    renderAnalysisTable(state.allAnalysisRecords);

    showToast("Analysis Synchronized", `Analyzed ${ana.total_samples} observations with ${ana.sla_compliance_percent}% SLA pass rate.`, "info", 2500);

  } catch (err) {
    console.error("Analysis load error:", err);
    showToast("Analysis Error", err.message, "danger");
  }
}

function setAnalysisTimeFilter(val, btn) {
  state.analysisTimeFilter = val;
  const pills = btn.parentElement.querySelectorAll(".filter-pill");
  pills.forEach((p) => p.classList.remove("active"));
  btn.classList.add("active");
  loadDeepAnalysis();
}

function renderAnalysisCharts(ana) {
  // Chart 1: Scatter (Throughput vs Latency)
  const ctxScatter = document.getElementById("analysisScatterChart");
  if (ctxScatter) {
    const scatterPoints = (ana.table_rows || []).map((r) => ({
      x: r.download_mbps + r.upload_mbps,
      y: r.latency_ms,
      severity: r.severity
    }));

    if (analysisScatterChart) {
      analysisScatterChart.data.datasets[0].data = scatterPoints;
      analysisScatterChart.update("none");
    } else {
      analysisScatterChart = new Chart(ctxScatter.getContext("2d"), {
        type: "scatter",
        data: {
          datasets: [
            {
              label: "Observations",
              data: scatterPoints,
              backgroundColor: (context) => {
                const item = context.raw;
                if (!item) return "#2563eb";
                if (item.severity === "HIGH") return "#ef4444";
                if (item.severity === "MEDIUM") return "#f59e0b";
                return "#10b981";
              },
              pointRadius: 5
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { title: { display: true, text: "Throughput (Mbps)" }, beginAtZero: true },
            y: { title: { display: true, text: "Latency (ms)" }, beginAtZero: true }
          }
        }
      });
    }
  }

  // Chart 2: Quantiles Spectrum
  const ctxQuant = document.getElementById("analysisQuantileChart");
  if (ctxQuant) {
    const quantLabels = ["Min", "Median (p50)", "p95 Tail", "Max Peak"];
    const latData = [ana.latency_stats.min, ana.latency_stats.p50, ana.latency_stats.p95, ana.latency_stats.max];
    const dlData = [ana.download_stats.min, ana.download_stats.p50, ana.download_stats.p95, ana.download_stats.max];

    if (analysisQuantileChart) {
      analysisQuantileChart.data.datasets[0].data = latData;
      analysisQuantileChart.data.datasets[1].data = dlData;
      analysisQuantileChart.update("none");
    } else {
      analysisQuantileChart = new Chart(ctxQuant.getContext("2d"), {
        type: "bar",
        data: {
          labels: quantLabels,
          datasets: [
            { label: "Latency (ms)", data: latData, backgroundColor: "#f59e0b" },
            { label: "Throughput (Mbps)", data: dlData, backgroundColor: "#2563eb" }
          ]
        },
        options: { responsive: true, maintainAspectRatio: false }
      });
    }
  }

  // Chart 3: Random Forest Feature Importance
  const ctxFeat = document.getElementById("analysisFeatureChart");
  if (ctxFeat) {
    const feats = ana.feature_importance || [];
    const featLabels = feats.map((f) => f.feature);
    const featWeights = feats.map((f) => f.weight);

    if (analysisFeatureChart) {
      analysisFeatureChart.data.labels = featLabels;
      analysisFeatureChart.data.datasets[0].data = featWeights;
      analysisFeatureChart.update("none");
    } else {
      analysisFeatureChart = new Chart(ctxFeat.getContext("2d"), {
        type: "bar",
        data: {
          labels: featLabels,
          datasets: [
            {
              label: "Feature Importance (%)",
              data: featWeights,
              backgroundColor: "rgba(37, 99, 235, 0.8)",
              borderRadius: 4
            }
          ]
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: { title: { display: true, text: "Gini Importance (%)" }, beginAtZero: true } }
        }
      });
    }
  }

  // Chart 4: Congestion Severity Distribution
  const ctxSev = document.getElementById("analysisSeverityChart");
  if (ctxSev) {
    const sc = ana.severity_counts;
    const sevData = [sc.Low, sc.Medium, sc.High];

    if (analysisSeverityChart) {
      analysisSeverityChart.data.datasets[0].data = sevData;
      analysisSeverityChart.update("none");
    } else {
      analysisSeverityChart = new Chart(ctxSev.getContext("2d"), {
        type: "doughnut",
        data: {
          labels: ["Low Congestion", "Medium Congestion", "High Congestion"],
          datasets: [
            {
              data: sevData,
              backgroundColor: ["#10b981", "#f59e0b", "#ef4444"]
            }
          ]
        },
        options: { responsive: true, maintainAspectRatio: false, cutout: "65%" }
      });
    }
  }
}

function renderAnalysisTable(records) {
  const tbody = document.getElementById("analysisTableBody");
  if (!tbody) return;

  if (!records || records.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted);">No records match filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  records.forEach((r) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.time}</td>
      <td>${r.interface}</td>
      <td class="font-mono">${r.download_mbps.toFixed(2)}</td>
      <td class="font-mono">${r.upload_mbps.toFixed(2)}</td>
      <td class="font-mono">${r.pps}</td>
      <td class="font-mono">${r.latency_ms.toFixed(1)}</td>
      <td class="font-mono">${r.jitter_ms.toFixed(1)}</td>
      <td class="font-mono">${r.loss_pct.toFixed(1)}%</td>
      <td><span class="badge ${r.severity === 'HIGH' ? 'badge-high' : (r.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low')}">${r.severity}</span></td>
      <td>${r.status}</td>
    `;
    tbody.appendChild(tr);
  });
}

function filterAnalysisTable() {
  const q = (document.getElementById("analysisTableSearch") && document.getElementById("analysisTableSearch").value.toLowerCase()) || "";
  if (!q) {
    renderAnalysisTable(state.allAnalysisRecords);
    return;
  }
  const filtered = state.allAnalysisRecords.filter((r) => {
    return (
      r.time.toLowerCase().includes(q) ||
      r.interface.toLowerCase().includes(q) ||
      r.severity.toLowerCase().includes(q) ||
      r.status.toLowerCase().includes(q)
    );
  });
  renderAnalysisTable(filtered);
}

// ---------------------------------------------------------------------------
// Reports Functionality (Requirement #4)
// ---------------------------------------------------------------------------

async function generateLiveReport() {
  try {
    const res = await fetch("/api/report/generate");
    if (!res.ok) throw new Error("Failed to generate report");
    const data = await res.json();
    const rep = data.report;

    const elId = document.getElementById("repId");
    const elDate = document.getElementById("repDate");
    const elIface = document.getElementById("repInterface");
    const elMode = document.getElementById("repMode");
    const elSla = document.getElementById("repSla");
    const elAcc = document.getElementById("repAccuracy");
    const elSamples = document.getElementById("repSamples");
    const elLat = document.getElementById("repLatency");
    const elP95 = document.getElementById("repP95");
    const elPeak = document.getElementById("repPeakTp");
    const elAvg = document.getElementById("repAvgTp");
    const elRecomm = document.getElementById("repRecommendationText");

    if (elId) elId.textContent = rep.report_id;
    if (elDate) elDate.textContent = rep.formatted_date;
    if (elIface) elIface.textContent = rep.interface;
    if (elMode) elMode.textContent = rep.mode.toUpperCase();
    if (elSla) elSla.textContent = `${rep.sla_score}%`;
    if (elAcc) elAcc.textContent = `${rep.model_accuracy}%`;
    if (elSamples) elSamples.textContent = rep.total_samples_analyzed;
    if (elLat) elLat.textContent = `${rep.avg_latency_ms}`;
    if (elP95) elP95.textContent = `${rep.p95_latency_ms} ms`;
    if (elPeak) elPeak.textContent = `${rep.peak_download_mbps}`;
    if (elAvg) elAvg.textContent = `${rep.avg_download_mbps} Mbps`;
    if (elRecomm) elRecomm.textContent = rep.recommendation;

    // Render incident rows
    const tbody = document.getElementById("repIncidentsTableBody");
    if (tbody) {
      if (rep.incidents && rep.incidents.length > 0) {
        tbody.innerHTML = "";
        rep.incidents.forEach((i) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${i.time}</td>
            <td><span class="badge ${i.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}">${i.severity}</span></td>
            <td class="font-mono">${i.throughput}</td>
            <td class="font-mono">${i.latency}</td>
            <td>${i.status}</td>
          `;
          tbody.appendChild(tr);
        });
      } else {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#10b981; font-weight:600;">No severe congestion excursions recorded during this audit session.</td></tr>`;
      }
    }

    showToast("Audit Report Compiled", `Report ${rep.report_id} generated. SLA Compliance: ${rep.sla_score}%.`, "success");

  } catch (err) {
    showToast("Report Generation Failed", err.message, "danger");
  }
}

// ---------------------------------------------------------------------------
// Settings Functionality (Requirement #4)
// ---------------------------------------------------------------------------

async function loadSettings() {
  try {
    const res = await fetch("/api/settings");
    if (!res.ok) return;
    const data = await res.json();
    const cfg = data.settings;

    const elPing = document.getElementById("settingPingTarget");
    const elPoll = document.getElementById("settingPollInterval");
    const elPollVal = document.getElementById("settingPollIntervalVal");
    const elLat = document.getElementById("settingLatencyThreshold");
    const elLoss = document.getElementById("settingLossThreshold");
    const elAudio = document.getElementById("settingAudioAlerts");

    if (elPing && cfg.ping_target) elPing.value = cfg.ping_target;
    if (elPoll && cfg.polling_interval) {
      elPoll.value = cfg.polling_interval;
      if (elPollVal) elPollVal.textContent = `${cfg.polling_interval}s`;
    }
    if (elLat && cfg.high_latency_threshold) elLat.value = cfg.high_latency_threshold;
    if (elLoss && cfg.high_loss_threshold) elLoss.value = cfg.high_loss_threshold;
    if (elAudio && cfg.audio_alerts_enabled !== undefined) elAudio.checked = cfg.audio_alerts_enabled;

  } catch (err) {
    console.warn("Failed loading settings:", err);
  }
}

async function saveSettings() {
  const pingTarget = (document.getElementById("settingPingTarget") && document.getElementById("settingPingTarget").value.trim()) || "8.8.8.8";
  const pollInterval = parseFloat((document.getElementById("settingPollInterval") && document.getElementById("settingPollInterval").value) || "1.0");
  const latThresh = parseFloat((document.getElementById("settingLatencyThreshold") && document.getElementById("settingLatencyThreshold").value) || "180.0");
  const lossThresh = parseFloat((document.getElementById("settingLossThreshold") && document.getElementById("settingLossThreshold").value) || "10.0");
  const audioAlerts = (document.getElementById("settingAudioAlerts") && document.getElementById("settingAudioAlerts").checked) || false;

  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ping_target: pingTarget,
        polling_interval: pollInterval,
        high_latency_threshold: latThresh,
        high_loss_threshold: lossThresh,
        audio_alerts_enabled: audioAlerts
      })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      state.pollIntervalMs = Math.round(pollInterval * 1000);
      startPollingLoop();
      showToast("Settings Saved", "Telemetry parameters and threshold levels updated.", "success");
    } else {
      showToast("Save Failed", data.message || "Failed to update configuration.", "danger");
    }
  } catch (err) {
    showToast("Network Error", err.message, "danger");
  }
}

function updatePollIntervalLabel(val) {
  const el = document.getElementById("settingPollIntervalVal");
  if (el) el.textContent = `${parseFloat(val).toFixed(1)}s`;
}

async function testPingTarget() {
  const target = (document.getElementById("settingPingTarget") && document.getElementById("settingPingTarget").value.trim()) || "8.8.8.8";
  const resEl = document.getElementById("testPingResult");
  if (resEl) resEl.textContent = `Pinging ${target}...`;

  try {
    const res = await fetch("/api/trigger/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "diagnostic_burst", target: target })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      const trig = data.trigger;
      if (resEl) {
        resEl.innerHTML = `<span style="color:#059669; font-weight:600;">✓ Reachable: Avg RTT = ${trig.avg_rtt_ms} ms (${trig.probes_received}/${trig.probes_sent} packets)</span>`;
      }
      showToast("Ping Test Success", `${target} replied with ${trig.avg_rtt_ms}ms round-trip time.`, "success");
    } else {
      if (resEl) resEl.innerHTML = `<span style="color:#dc2626;">✗ Ping failed to reach ${target}.</span>`;
      showToast("Ping Test Failed", `Could not reach ${target}.`, "danger");
    }
  } catch (err) {
    if (resEl) resEl.innerHTML = `<span style="color:#dc2626;">Error: ${err.message}</span>`;
  }
}

function resetSettings() {
  const elPing = document.getElementById("settingPingTarget");
  const elPoll = document.getElementById("settingPollInterval");
  const elPollVal = document.getElementById("settingPollIntervalVal");
  const elLat = document.getElementById("settingLatencyThreshold");
  const elLoss = document.getElementById("settingLossThreshold");
  const elAudio = document.getElementById("settingAudioAlerts");

  if (elPing) elPing.value = "8.8.8.8";
  if (elPoll) {
    elPoll.value = "1.0";
    if (elPollVal) elPollVal.textContent = "1.0s";
  }
  if (elLat) elLat.value = "180.0";
  if (elLoss) elLoss.value = "10.0";
  if (elAudio) elAudio.checked = false;

  showToast("Defaults Restored", "Settings form restored to baseline defaults.", "info");
}

function playAlertBeep() {
  const elAudio = document.getElementById("settingAudioAlerts");
  if (!elAudio || !elAudio.checked) return;

  try {
    if (!state.audioContext) {
      state.audioContext = new (window.AudioContext || window.webkitAudioContext)();
    }
    const osc = state.audioContext.createOscillator();
    const gain = state.audioContext.createGain();
    osc.connect(gain);
    gain.connect(state.audioContext.destination);

    osc.frequency.setValueAtTime(587.33, state.audioContext.currentTime); // D5
    osc.frequency.setValueAtTime(880.00, state.audioContext.currentTime + 0.1); // A5
    gain.gain.setValueAtTime(0.15, state.audioContext.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, state.audioContext.currentTime + 0.35);

    osc.start(state.audioContext.currentTime);
    osc.stop(state.audioContext.currentTime + 0.35);
  } catch (err) {
    console.warn("Audio alert error:", err);
  }
}

function testAudioAlert() {
  const prev = document.getElementById("settingAudioAlerts").checked;
  document.getElementById("settingAudioAlerts").checked = true;
  playAlertBeep();
  document.getElementById("settingAudioAlerts").checked = prev;
  showToast("Audio Test", "Played alert chime.", "info");
}

// ---------------------------------------------------------------------------
// Toast Notification Engine
// ---------------------------------------------------------------------------

function showToast(title, message, type = "info", duration = 3500) {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast-item toast-${type}`;

  const iconMap = {
    success: "✓",
    danger: "✗",
    warning: "⚠",
    info: "ℹ"
  };

  toast.innerHTML = `
    <div style="font-weight: 700; color: var(--primary); font-size: 1.1rem; line-height: 1;">${iconMap[type] || 'ℹ'}</div>
    <div class="toast-content" style="flex:1;">
      <div class="toast-title">${escapeHtml(title)}</div>
      <div class="toast-msg">${escapeHtml(message)}</div>
    </div>
    <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    if (toast.parentElement) {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(30px)";
      setTimeout(() => toast.remove(), 250);
    }
  }, duration);
}

// ---------------------------------------------------------------------------
// Dashboard Actions (Start, Stop, Mode, Refresh, Clear)
// ---------------------------------------------------------------------------

async function handleRefresh() {
  await pollStatsNow();
  if (state.currentTab === "analysis") {
    loadDeepAnalysis();
  }
  showToast("Telemetry Refreshed", "Synchronized latest observations and chart telemetry.", "info", 2000);
}

function setDashboardTimeFilter(filterVal, btn) {
  if (btn) {
    const pills = btn.parentElement.querySelectorAll(".filter-pill");
    pills.forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
  }
  if (filterVal === "60") {
    state.historyMaxPoints = 15;
  } else if (filterVal === "300") {
    state.historyMaxPoints = 30;
  } else if (filterVal === "900") {
    state.historyMaxPoints = 50;
  } else {
    state.historyMaxPoints = 60;
  }
  pollStatsNow();
}

function setDashboardSeverityFilter(sev) {
  state.dashboardSeverityFilter = sev;
  pollStatsNow();
}

async function startMonitoring() {
  const iface = (elements.interfaceSelect && elements.interfaceSelect.value) ? elements.interfaceSelect.value : state.selectedInterface;
  elements.btnStart.disabled = true;

  try {
    const res = await fetch("/api/monitor/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface, mode: state.mode })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast("Start Failed", data.message, "danger");
      elements.btnStart.disabled = false;
      return;
    }
    setMonitoringUI(true);
    pollStatsNow();
    showToast("Monitoring Active", `Started real-time monitoring on ${iface}.`, "success");
  } catch (err) {
    showToast("Network Error", err.message, "danger");
    elements.btnStart.disabled = false;
  }
}

async function stopMonitoring() {
  elements.btnStop.disabled = true;
  try {
    const res = await fetch("/api/monitor/stop", { method: "POST" });
    const data = await res.json();
    if (!res.ok) {
      showToast("Stop Failed", data.message, "danger");
    } else {
      showToast("Monitoring Stopped", "Background measurement loop paused.", "warning");
    }
    setMonitoringUI(false);
  } catch (err) {
    showToast("Error", err.message, "danger");
  } finally {
    elements.btnStop.disabled = false;
  }
}

async function setMode(mode) {
  try {
    const res = await fetch("/api/mode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode })
    });
    const data = await res.json();
    if (res.ok) {
      setModeUI(mode);
      pollStatsNow();
      showToast("Mode Switched", `Active telemetry operating in ${mode.toUpperCase()} mode.`, "info");
    } else {
      showToast("Mode Switch Failed", data.message, "danger");
    }
  } catch (err) {
    showToast("Error", err.message, "danger");
  }
}

async function changeDemoScenario(scenario) {
  try {
    await fetch("/api/demo/scenario", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario })
    });
    pollStatsNow();
    showToast("Simulated Load Scenario", `Switched to ${scenario.toUpperCase()} scenario.`, "info", 2000);
  } catch (err) {
    console.error("Scenario change failed:", err);
  }
}

async function clearHistory() {
  try {
    await fetch("/api/history/clear", { method: "POST" });
    throughputChart.data.labels = [];
    throughputChart.data.datasets.forEach((ds) => ds.data = []);
    throughputChart.update();

    ppsChart.data.labels = [];
    ppsChart.data.datasets.forEach((ds) => ds.data = []);
    ppsChart.update();

    latencyChart.data.labels = [];
    latencyChart.data.datasets.forEach((ds) => ds.data = []);
    latencyChart.update();

    congestionChart.data.labels = [];
    congestionChart.data.datasets.forEach((ds) => ds.data = []);
    congestionChart.update();

    showToast("History Cleared", "In-memory telemetry buffer reset.", "info");
  } catch (err) {
    console.error("Clear history failed:", err);
  }
}

async function saveLabelledObservation() {
  const label = elements.userLabelSelect.value;
  try {
    const res = await fetch("/api/observations/label", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label, features: state.latestStats })
    });
    const data = await res.json();
    if (res.ok) {
      showToast("Sample Labelled", `Total ground-truth samples: ${data.total_labelled_samples}.`, "success");
    } else {
      showToast("Save Failed", data.message, "danger");
    }
  } catch (err) {
    showToast("Network Error", err.message, "danger");
  }
}

async function triggerRetrain() {
  if (!confirm("Retrain Random Forest model on your recorded labelled observations?")) return;
  try {
    const res = await fetch("/api/model/retrain", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      showToast("Model Retrained", `Accuracy: ${(data.test_accuracy * 100).toFixed(1)}%. Model hot-reloaded!`, "success", 5000);
      pollStatsNow();
    } else {
      showToast("Retraining Not Ready", data.message, "warning", 5000);
    }
  } catch (err) {
    showToast("Error", err.message, "danger");
  }
}

function dismissBanner() {
  elements.degradedBanner.classList.add("hidden");
}

// ---------------------------------------------------------------------------
// UI State & Formatter Helpers
// ---------------------------------------------------------------------------

function setMonitoringUI(isRunning) {
  state.isMonitoring = isRunning;
  elements.btnStart.disabled = isRunning;
  elements.btnStop.disabled = !isRunning;

  if (isRunning) {
    elements.monitorPill.className = "status-pill pill-running";
    elements.monitorPillText.textContent = "● LIVE DYNAMIC STREAMING (1.0s)";
  } else {
    elements.monitorPill.className = "status-pill pill-stopped";
    elements.monitorPillText.textContent = "MONITORING STOPPED";
  }
}

function setModeUI(mode) {
  state.mode = mode.toLowerCase();
  if (state.mode === "live") {
    elements.modePill.className = "status-pill pill-live";
    elements.modePillText.textContent = "LIVE NETWORK DATA";
    elements.btnLiveMode.classList.add("active");
    elements.btnDemoMode.classList.remove("active");
    elements.demoScenarioGroup.classList.add("hidden");
  } else {
    elements.modePill.className = "status-pill pill-demo";
    elements.modePillText.textContent = "DEMO DATA — NOT LIVE";
    elements.btnDemoMode.classList.add("active");
    elements.btnLiveMode.classList.remove("active");
    elements.demoScenarioGroup.classList.remove("hidden");
    elements.degradedBanner.classList.add("hidden");
  }
}

function getBadgeClass(severity) {
  if (severity === "HIGH") return "badge-high";
  if (severity === "MEDIUM") return "badge-medium";
  return "badge-low";
}

function getAlertClass(severity) {
  if (severity === "HIGH") return "alert-high";
  if (severity === "MEDIUM" || severity === "WARNING") return "alert-warning";
  return "alert-info";
}

function formatNumber(num, decimals = 1) {
  if (num === null || num === undefined || isNaN(num)) return "N/A";
  return Number(num).toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  });
}

function formatBytesPerSec(bytes) {
  if (!bytes || isNaN(bytes)) return "0 KB/s";
  const kb = bytes / 1024;
  if (kb > 1024) {
    return `${(kb / 1024).toFixed(2)} MB/s`;
  }
  return `${kb.toFixed(1)} KB/s`;
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}
