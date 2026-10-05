"""Convert packet rows into fixed-width, time-window behavior features."""

from __future__ import annotations

import math

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "packet_rate", "avg_payload_size", "std_packet_size", "syn_count", "ack_count",
    "syn_ack_ratio", "syn_fraction", "ack_fraction", "syn_ack_fraction",
    "fin_fraction", "rst_fraction", "psh_fraction", "protocol_entropy",
    "unique_src_ips", "unique_dst_ports", "top_source_share", "ssh_packets", "ssh_share",
]


def _flag_set(value: object) -> set[str]:
    if pd.isna(value) or not str(value).strip():
        return set()
    return {part.strip().upper() for part in str(value).replace(",", "|").split("|")}


def extract_features(packets: pd.DataFrame, window_seconds: int = 1) -> pd.DataFrame:
    """Aggregate packets into time windows, retaining labels and useful context."""
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")
    if packets.empty:
        return pd.DataFrame(columns=["timestamp", "top_source_ip", "dominant_dst_port", *FEATURE_COLUMNS])
    required = {"timestamp", "src_ip", "dst_port", "protocol", "packet_size", "tcp_flags"}
    missing = required.difference(packets.columns)
    if missing:
        raise ValueError(f"Missing packet columns: {', '.join(sorted(missing))}")

    frame = packets.copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    frame = frame.dropna(subset=["timestamp"])
    if frame.empty:
        return pd.DataFrame(columns=["timestamp", "top_source_ip", "dominant_dst_port", *FEATURE_COLUMNS])
    frame["window"] = frame["timestamp"].dt.floor(f"{window_seconds}s")
    output: list[dict[str, object]] = []
    for window, group in frame.groupby("window", sort=True):
        count = len(group)
        flags = group["tcp_flags"].map(_flag_set)
        flag_counts = {name: int(flags.map(lambda item, key=name: key in item).sum()) for name in ("SYN", "ACK", "SYN-ACK", "FIN", "RST", "PSH")}
        source_counts = group["src_ip"].astype(str).value_counts()
        protocol_counts = group["protocol"].astype(str).str.upper().value_counts(normalize=True)
        entropy = float(-(protocol_counts * np.log2(protocol_counts)).sum()) if len(protocol_counts) else 0.0
        port_counts = group["dst_port"].value_counts()
        ssh_packets = int((pd.to_numeric(group["dst_port"], errors="coerce") == 22).sum())
        syn_count = flag_counts["SYN"]
        ack_count = flag_counts["ACK"] + flag_counts["SYN-ACK"]
        row: dict[str, object] = {
            "timestamp": window,
            "top_source_ip": str(source_counts.index[0]),
            "dominant_dst_port": int(port_counts.index[0]),
            "packet_rate": count / window_seconds,
            "avg_payload_size": float(group["packet_size"].mean()),
            "std_packet_size": float(group["packet_size"].std(ddof=0)),
            "syn_count": syn_count,
            "ack_count": ack_count,
            "syn_ack_ratio": float(syn_count / max(ack_count, 1)),
            "syn_fraction": flag_counts["SYN"] / count,
            "ack_fraction": flag_counts["ACK"] / count,
            "syn_ack_fraction": flag_counts["SYN-ACK"] / count,
            "fin_fraction": flag_counts["FIN"] / count,
            "rst_fraction": flag_counts["RST"] / count,
            "psh_fraction": flag_counts["PSH"] / count,
            "protocol_entropy": entropy,
            "unique_src_ips": int(group["src_ip"].nunique()),
            "unique_dst_ports": int(group["dst_port"].nunique()),
            "top_source_share": float(source_counts.iloc[0] / count),
            "ssh_packets": ssh_packets,
            "ssh_share": ssh_packets / count,
        }
        if "ground_truth_attack" in group:
            row["ground_truth_attack"] = bool(group["ground_truth_attack"].astype(bool).any())
            if "ground_truth_type" in group:
                labels = group.loc[group["ground_truth_attack"].astype(bool), "ground_truth_type"]
                row["ground_truth_type"] = str(labels.iloc[0]) if not labels.empty else "Normal"
        output.append(row)
    return pd.DataFrame(output)


def model_matrix(features: pd.DataFrame) -> pd.DataFrame:
    """Select and sanitize the numeric columns used by the detector."""
    matrix = features.reindex(columns=FEATURE_COLUMNS).apply(pd.to_numeric, errors="coerce")
    return matrix.replace([np.inf, -np.inf], np.nan).fillna(0.0)