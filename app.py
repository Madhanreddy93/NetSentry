"""Streamlit dashboard for safe, simulation-only NetSentry demonstrations."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from netsentry.classifier import classify_attack
from netsentry.features import extract_features
from netsentry.loader import load_traffic
from netsentry.mitigation import log_rules, generate_rules
from netsentry.model import DEFAULT_MODEL_PATH, AnomalyDetector, evaluate_model, load_or_train, train_default_model
from netsentry.simulator import generate_traffic

ROOT = Path(__file__).resolve().parent
METRICS_PATH = ROOT / "data" / "metrics.json"
RULE_LOG_PATH = ROOT / "data" / "rule_log.json"
ATTACK_COLORS = {"SYN Flood": "#D6304A", "Port Scan": "#F28C45", "SSH Brute Force": "#F5B942", "DDoS (volumetric)": "#D6304A", "Unknown anomaly": "#F5B942"}
SCENARIO_LABELS = {"Normal": "normal", "SYN Flood": "syn_flood", "Port Scan": "port_scan", "SSH Brute Force": "ssh_brute_force", "Mixed": "mixed"}

st.set_page_config(page_title="NetSentry", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
.stApp { background: #0B1F3A; }
.block-container { padding-top: 1.4rem; padding-bottom: 2rem; max-width: 1600px; }
.hero { padding: 0.2rem 0 0.8rem; }
.hero h1 { margin: 0; color: #F4F8FC; font-size: 2.15rem; letter-spacing: 0; }
.hero p { margin: .25rem 0 0; color: #9FB4C9; font-size: 1rem; }
.kpi { background: #102944; border: 1px solid #24435D; border-radius: 9px; padding: 15px 17px; min-height: 104px; }
.kpi-label { color: #A9BDCF; font-size: .85rem; }
.kpi-value { color: #F4F8FC; font-size: 1.65rem; font-weight: 700; padding-top: 8px; }
.status { border-radius: 9px; padding: 15px 18px; margin: .5rem 0 1rem; font-weight: 700; font-size: 1.2rem; }
.healthy { color: #A5F1D9; background: #0E3A3A; border: 1px solid #0E9F8E; }
.alert { color: #FFE8EC; background: #4A1D2B; border: 1px solid #D6304A; }
@keyframes alert-pulse { 50% { box-shadow: 0 0 0 3px rgba(214,48,74,.28); } }
.alert { animation: alert-pulse 1.4s ease-in-out infinite; }
.severity { display: inline-block; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: .78rem; }
.sev-low { background: #145247; color: #A5F1D9; }.sev-medium { background: #594517; color: #FFE39B; }
.sev-high { background: #60351F; color: #FFD0A5; }.sev-critical { background: #642537; color: #FFE0E6; }
.small-note { color: #A9BDCF; font-size: .86rem; }
div[data-testid="stVerticalBlock"] > div:has(> div > .kpi) { gap: 0; }
</style>
""", unsafe_allow_html=True)


def _init_state() -> None:
    defaults = {
        "running": True, "tick": 0, "packets": pd.DataFrame(), "features": pd.DataFrame(),
        "alerts": [], "rule_events": [], "last_alert_key": None, "injected": None,
        "started_at": datetime.now().replace(microsecond=0), "loaded_upload": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _metric_tiles(values: list[tuple[str, str]]) -> None:
    columns = st.columns(len(values))
    for column, (label, value) in zip(columns, values):
        column.markdown(f'<div class="kpi"><div class="kpi-label">{label}</div><div class="kpi-value">{value}</div></div>', unsafe_allow_html=True)


def _load_metrics() -> dict[str, object]:
    try:
        return json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


@st.cache_data(show_spinner=False)
def _cached_metrics(model_type: str, sensitivity: float) -> dict[str, object]:
    return evaluate_model(_get_detector(model_type), METRICS_PATH, sensitivity)


def _metrics_for(model_type: str, sensitivity: float) -> dict[str, object]:
    saved = _load_metrics()
    if saved.get("model") == model_type and float(saved.get("sensitivity", -1)) == sensitivity:
        return saved
    metrics = _cached_metrics(model_type, sensitivity)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


@st.cache_resource
def _get_detector(model_type: str) -> AnomalyDetector:
    path = DEFAULT_MODEL_PATH if model_type == "Isolation Forest" else ROOT / "models" / "one_class_svm.joblib"
    return load_or_train(path) if path.exists() else train_default_model(model_type, path=path)


def _feature_view(detector: AnomalyDetector, sensitivity: float) -> pd.DataFrame:
    features = st.session_state.features.copy()
    if features.empty:
        return features
    predictions = detector.predict(features, sensitivity)
    return pd.concat([features.reset_index(drop=True), predictions.reset_index(drop=True)], axis=1)


def _append_alert_and_rules(row: pd.Series) -> None:
    details = classify_attack(row.to_dict())
    alert_key = f"{row['timestamp']}|{details['attack_type']}"
    if alert_key == st.session_state.last_alert_key:
        return
    st.session_state.last_alert_key = alert_key
    source_ip = str(row.get("top_source_ip", "198.51.100.42"))
    generated = generate_rules(details["attack_type"], source_ip, details["reason"])
    event = log_rules(details["attack_type"], details["reason"], source_ip, generated["rules"], RULE_LOG_PATH)
    event.update({"warning": generated["warning"], "severity": details["severity"]})
    st.session_state.rule_events.insert(0, event)
    st.session_state.alerts.insert(0, {"timestamp": str(row["timestamp"]), **details, "source_ip": source_ip})


def _advance_simulation(scenario: str, window_seconds: int) -> None:
    tick = st.session_state.tick
    active = st.session_state.injected or scenario
    now = st.session_state.started_at + timedelta(seconds=tick)
    batch = generate_traffic(1, active, seed=4000 + tick, start_time=now)
    if st.session_state.injected:
        st.session_state.injected = None
    packets = pd.concat([st.session_state.packets, batch], ignore_index=True)
    cutoff = now - timedelta(seconds=180)
    packets["timestamp"] = pd.to_datetime(packets["timestamp"])
    packets = packets.loc[packets["timestamp"] >= cutoff].reset_index(drop=True)
    st.session_state.packets = packets
    st.session_state.features = extract_features(packets, window_seconds)
    st.session_state.tick += 1


def _status_and_frame(frame: pd.DataFrame) -> tuple[pd.DataFrame, str, str]:
    if frame.empty:
        return frame, "ALL NORMAL", "healthy"
    flagged = frame[frame["is_anomaly"].astype(bool)]
    if flagged.empty:
        return frame, "ALL NORMAL", "healthy"
    latest = flagged.iloc[-1]
    details = classify_attack(latest.to_dict())
    _append_alert_and_rules(latest)
    return frame, f"UNDER ATTACK: {details['attack_type']} · {details['severity']}", "alert"


def _read_uploaded(uploaded) -> pd.DataFrame:
    if st.session_state.loaded_upload is uploaded:
        return st.session_state.packets
    packets = load_traffic(uploaded, uploaded.name)
    st.session_state.loaded_upload = uploaded
    st.session_state.packets = packets
    st.session_state.features = extract_features(packets, int(st.session_state.window_seconds))
    return packets


_init_state()
st.markdown('<div class="hero"><h1>NetSentry</h1><p>Catching network attacks before servers crash</p></div>', unsafe_allow_html=True)

with st.sidebar:
    st.header("Traffic controls")
    mode = st.selectbox("Mode", ["Live Simulation", "Replay Scenario", "Upload PCAP/CSV"])
    scenario_label = st.selectbox("Scenario", list(SCENARIO_LABELS))
    sensitivity = st.slider("Detection sensitivity", 0.01, 0.20, 0.01, 0.01, help="Higher sensitivity flags more unusual windows, and may also increase false alarms.")
    model_type = st.selectbox("Detection model", ["Isolation Forest", "One-Class SVM"], help="Both models learn the shape of normal traffic without attack IP lists.")
    window_label = st.selectbox("Time window", ["1s", "2s", "5s"])
    window_seconds = int(window_label[:-1])
    st.session_state.window_seconds = window_seconds
    button_cols = st.columns(2)
    if button_cols[0].button("Start", width="stretch"):
        st.session_state.running = True
    if button_cols[1].button("Pause", width="stretch"):
        st.session_state.running = False
    if st.button("Reset", width="stretch"):
        for key in ("packets", "features", "alerts", "rule_events"):
            st.session_state[key] = pd.DataFrame() if key in ("packets", "features") else []
        st.session_state.tick = 0
        st.session_state.last_alert_key = None
        st.session_state.started_at = datetime.now().replace(microsecond=0)
        st.session_state.injected = None
    if st.button("Inject attack now", type="primary", width="stretch"):
        st.session_state.injected = SCENARIO_LABELS[scenario_label] if scenario_label != "Normal" else "syn_flood"
        st.session_state.running = True
    if mode == "Upload PCAP/CSV":
        uploaded_file = st.file_uploader("Choose a CSV or packet capture", type=["csv", "pcap", "pcapng", "cap"])
    else:
        uploaded_file = None
    with st.expander("How to read this dashboard"):
        st.write("Green means the traffic looks like the normal pattern the model learned. Red means a traffic window looked unusual; the attack name is a rule-based best guess.")
        st.write("SYN starts a TCP connection; ACK confirms a reply. An anomaly score measures how far a window is from learned normal traffic. Protocol entropy summarizes how varied the protocols are.")
        st.caption("Only packet headers and counts are used. Nothing is sent to a network.")

try:
    detector = _get_detector(model_type)
except Exception as error:
    st.error(f"The detector could not be prepared: {error}")
    st.stop()

if mode == "Live Simulation" and st.session_state.running:
    _advance_simulation(SCENARIO_LABELS[scenario_label], window_seconds)
elif mode == "Replay Scenario" and st.session_state.tick == 0:
    replay = generate_traffic(60, SCENARIO_LABELS[scenario_label], seed=77, start_time=datetime.now().replace(microsecond=0))
    st.session_state.packets = replay
    st.session_state.features = extract_features(replay, window_seconds)
    st.session_state.tick = 1
elif mode == "Upload PCAP/CSV" and uploaded_file is not None:
    try:
        _read_uploaded(uploaded_file)
    except Exception as error:
        st.error(f"Could not read this file: {error}")

if mode == "Live Simulation" and st.session_state.running:
    st_autorefresh(interval=1000, key="netsentry_refresh")

try:
    evaluated = _feature_view(detector, sensitivity)
    evaluated, status_text, status_class = _status_and_frame(evaluated)
except Exception as error:
    st.error(f"Could not analyze the current traffic: {error}")
    evaluated, status_text, status_class = pd.DataFrame(), "ALL NORMAL", "healthy"

status_color = "#D6304A" if status_class == "alert" else "#0E9F8E"
st.markdown(f'<div class="status {status_class}" style="border-left:7px solid {status_color}">{status_text}</div>', unsafe_allow_html=True)

latest = evaluated.iloc[-1] if not evaluated.empty else pd.Series(dtype=object)
active_ips = int(evaluated.loc[evaluated.get("is_anomaly", pd.Series(dtype=bool)).astype(bool), "top_source_ip"].nunique()) if not evaluated.empty and "is_anomaly" in evaluated else 0
try:
    metrics = _metrics_for(model_type, sensitivity)
except Exception as error:
    metrics = {}
    metrics_error = str(error)
else:
    metrics_error = ""
ratio = float(latest.get("syn_ack_ratio", 0)) if not evaluated.empty else 0
_metric_tiles([
    ("Packets per second", f"{float(latest.get('packet_rate', 0)):,.0f}" if not evaluated.empty else "0"),
    ("Active suspicious IPs", str(active_ips)),
    ("Anomalous windows", str(int(evaluated.get("is_anomaly", pd.Series(dtype=bool)).sum())) if not evaluated.empty else "0"),
    ("SYN / ACK ratio", f"{ratio:.1f}"),
    ("Rule sets generated", str(len(st.session_state.rule_events))),
    ("Detection precision", f"{float(metrics.get('precision', 0)):.0%}" if metrics else "Run evaluation"),
])

st.subheader("Live traffic")
if evaluated.empty:
    st.info("Waiting for traffic. Start the simulation or upload a PCAP/CSV file to begin.")
else:
    plot = evaluated.copy()
    plot["window label"] = plot["is_anomaly"].map({True: "Anomalous window", False: "Normal window"})
    chart = go.Figure()
    chart.add_trace(go.Scatter(x=plot["timestamp"], y=plot["packet_rate"], mode="lines", name="Packets per second", line={"color": "#39C6B4", "width": 2}, fill="tozeroy", fillcolor="rgba(14,159,142,.12)"))
    anomalies = plot[plot["is_anomaly"]]
    if not anomalies.empty:
        chart.add_trace(go.Scatter(x=anomalies["timestamp"], y=anomalies["packet_rate"], mode="markers", name="Anomalous window", marker={"color": "#D6304A", "size": 10, "symbol": "diamond"}))
        for _, anomaly in anomalies.iterrows():
            chart.add_vrect(x0=anomaly["timestamp"], x1=anomaly["timestamp"] + pd.Timedelta(seconds=window_seconds), fillcolor="#D6304A", opacity=0.10, line_width=0)
    chart.update_layout(title="Traffic rate over time", xaxis_title="Time", yaxis_title="Packets per second (packets/s)", legend_title="Traffic", template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(16,41,68,.35)", margin={"t": 55, "b": 25})
    rate_max = float(plot["packet_rate"].quantile(.95))
    if float(latest.get("packet_rate", 0)) > max(rate_max, 500):
        chart.add_annotation(text="Bandwidth spike warning", x=latest["timestamp"], y=latest["packet_rate"], showarrow=True, arrowcolor="#F5B942", font={"color": "#F5B942"})
    st.plotly_chart(chart, use_container_width=True)

left, right = st.columns(2)
with left:
    st.subheader("Anomaly score", help="A higher score means the traffic window is farther from the normal pattern the model learned.")
    if evaluated.empty:
        st.info("Scores appear after the first traffic window.")
    else:
        score_chart = go.Figure()
        score_chart.add_trace(go.Scatter(x=evaluated["timestamp"], y=evaluated["anomaly_score"], mode="lines+markers", name="Anomaly score", line={"color": "#53B9E8"}))
        score_chart.add_hline(y=float(evaluated["threshold"].iloc[-1]), line_dash="dash", line_color="#F5B942", annotation_text="Sensitivity threshold")
        score_chart.update_layout(title="Unusualness score by window", xaxis_title="Time", yaxis_title="Anomaly score (higher is less normal)", template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(16,41,68,.35)", margin={"t": 50})
        st.plotly_chart(score_chart, use_container_width=True)
with right:
    st.subheader("Normal vs. anomalous windows")
    counts = evaluated["is_anomaly"].value_counts().rename(index={True: "Anomalous", False: "Normal"}) if not evaluated.empty else pd.Series(dtype=int)
    st.plotly_chart(px.pie(values=counts.values, names=counts.index, hole=.55, color=counts.index, color_discrete_map={"Normal": "#0E9F8E", "Anomalous": "#D6304A"}, title="Window classification"), use_container_width=True)

st.subheader("Flow metrics", help="SYN starts a TCP connection; ACK is a reply. SYN/ACK compares starts with replies. Protocol entropy describes how varied the protocol mix is.")
flow_a, flow_b, flow_c = st.columns(3)
if evaluated.empty:
    flow_a.info("Protocol mix will appear here.")
    flow_b.info("TCP flag counts will appear here.")
    flow_c.info("Packet size history will appear here.")
else:
    current_packets = st.session_state.packets.copy()
    protocol_counts = current_packets["protocol"].astype(str).value_counts()
    flow_a.plotly_chart(px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Protocol distribution", color_discrete_sequence=["#0E9F8E", "#53B9E8", "#F5B942"]), use_container_width=True)
    flag_counts = current_packets["tcp_flags"].fillna("").value_counts().head(8)
    flow_b.plotly_chart(px.bar(x=flag_counts.index, y=flag_counts.values, title="TCP flag distribution", labels={"x": "TCP flag", "y": "Packets"}, color_discrete_sequence=["#53B9E8"]), use_container_width=True)
    flow_c.plotly_chart(px.line(evaluated, x="timestamp", y="avg_payload_size", title="Average packet size", labels={"timestamp": "Time", "avg_payload_size": "Average packet size (bytes)"}, color_discrete_sequence=["#F5B942"]), use_container_width=True)

st.subheader("Top suspicious IPs")
if evaluated.empty or not (evaluated["is_anomaly"]).any():
    st.info("No suspicious sources are currently flagged.")
else:
    suspicious = evaluated[evaluated["is_anomaly"]].groupby("top_source_ip", as_index=False).agg(packets=("packet_rate", "sum"), unique_ports=("unique_dst_ports", "max"), share=("top_source_share", "max"), latest_type=("timestamp", "count")).sort_values("packets", ascending=False).head(10)
    rows = []
    for _, item in suspicious.iterrows():
        source_row = evaluated[evaluated["top_source_ip"] == item["top_source_ip"]].iloc[-1]
        details = classify_attack(source_row.to_dict())
        rows.append({"IP": item["top_source_ip"], "Packets": int(item["packets"]), "Share %": f"{item['share']:.1%}", "Unique ports": int(item["unique_ports"]), "Attack type": details["attack_type"], "Severity": details["severity"]})
    severity_colors = {
        "Low": "background-color: #145247; color: #A5F1D9;",
        "Medium": "background-color: #594517; color: #FFE39B;",
        "High": "background-color: #60351F; color: #FFD0A5;",
        "Critical": "background-color: #642537; color: #FFE0E6;",
    }
    suspicious_table = pd.DataFrame(rows).style.map(lambda value: severity_colors.get(str(value), ""), subset=["Severity"])
    st.dataframe(suspicious_table, width="stretch", hide_index=True)

st.subheader("Mitigation rules")
if st.session_state.rule_events:
    latest_event = st.session_state.rule_events[0]
    if latest_event.get("warning"):
        st.warning(latest_event["warning"])
    st.caption("Commands below are generated text only. NetSentry never executes firewall or system commands.")
    rule_text = "\n".join(latest_event["rules"])
    st.code(rule_text, language="bash")
    st.download_button("Download block_rules.sh", data="# Generated by NetSentry; review before use.\n" + rule_text + "\n", file_name="block_rules.sh", mime="text/x-shellscript")
    log_rows = [{"Timestamp": event["timestamp"], "Attack type": event["attack_type"], "Source IP": event["source_ip"], "Reason": event["reason"]} for event in st.session_state.rule_events]
    st.dataframe(pd.DataFrame(log_rows), width="stretch", hide_index=True)
else:
    st.info("A rule set will appear when an anomalous source is identified.")

st.subheader("Alerts timeline")
if st.session_state.alerts:
    for alert in st.session_state.alerts[:12]:
        st.markdown(f"**{alert['timestamp']} · {alert['attack_type']}**  \n{alert['reason']}  \nSource: `{alert['source_ip']}` · Severity: **{alert['severity']}**")
else:
    st.info("No alerts yet. Normal traffic is a useful baseline for the demo.")

st.subheader("Model performance")
if metrics:
    metric_cols = st.columns(4)
    metric_cols[0].metric("Precision", f"{float(metrics['precision']):.1%}")
    metric_cols[1].metric("Recall", f"{float(metrics['recall']):.1%}")
    metric_cols[2].metric("F1 score", f"{float(metrics['f1']):.1%}")
    metric_cols[3].metric("False positive rate", f"{float(metrics['false_positive_rate']):.1%}")
    matrix = metrics["confusion_matrix"]
    heatmap = go.Figure(data=go.Heatmap(z=matrix, x=["Predicted normal", "Predicted attack"], y=["Actual normal", "Actual attack"], colorscale=[[0, "#102944"], [.5, "#0E9F8E"], [1, "#D6304A"]], text=matrix, texttemplate="%{text}", showscale=False))
    heatmap.update_layout(title="Confusion matrix (windows)", xaxis_title="Model result", yaxis_title="Known traffic label", template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", margin={"t": 50})
    st.plotly_chart(heatmap, use_container_width=True)
else:
    st.warning(f"Evaluation metrics are not available yet: {metrics_error}")

st.markdown("<hr><p class='small-note'>Simulation only. No real attacks are performed.</p>", unsafe_allow_html=True)