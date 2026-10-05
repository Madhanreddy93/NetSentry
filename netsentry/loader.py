"""Offline CSV and optional PCAP readers; no packet capture is initiated."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

ALIASES = {
    "src_ip": ("src_ip", "source ip", "source_ip", "src ip"),
    "dst_ip": ("dst_ip", "destination ip", "destination_ip", "dst ip"),
    "src_port": ("src_port", "source port", "source_port", "src port"),
    "dst_port": ("dst_port", "destination port", "destination_port", "dst port"),
    "protocol": ("protocol", "proto"),
    "packet_size": ("packet_size", "length", "totlen", "total length"),
    "tcp_flags": ("tcp_flags", "flags", "tcp flags"),
    "timestamp": ("timestamp", "time", "flow start time"),
}


def load_csv(source: str | Path | object) -> pd.DataFrame:
    """Read and normalize a packet CSV, including common IDS column names."""
    frame = pd.read_csv(source)
    normalized = {str(column).strip().lower(): column for column in frame.columns}
    rename: dict[object, str] = {}
    for target, candidates in ALIASES.items():
        match = next((normalized[name] for name in candidates if name in normalized), None)
        if match is not None:
            rename[match] = target
    frame = frame.rename(columns=rename)
    required = {"timestamp", "src_ip", "dst_port", "protocol", "packet_size"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"CSV needs packet columns for: {', '.join(sorted(missing))}")
    defaults = {"dst_ip": "0.0.0.0", "src_port": 0, "tcp_flags": ""}
    for column, value in defaults.items():
        if column not in frame:
            frame[column] = value
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    frame["dst_port"] = pd.to_numeric(frame["dst_port"], errors="coerce").fillna(0).astype(int)
    frame["packet_size"] = pd.to_numeric(frame["packet_size"], errors="coerce").fillna(0)
    if "label" in frame.columns:
        frame["ground_truth_attack"] = ~frame["label"].astype(str).str.lower().isin(["normal", "benign", "0"])
        frame["ground_truth_type"] = frame["label"].astype(str)
    elif "label" not in frame and "ground_truth_attack" not in frame:
        frame["ground_truth_attack"] = False
    return frame.dropna(subset=["timestamp", "src_ip"])


def load_pcap(source: str | Path | object) -> pd.DataFrame:
    """Read an existing PCAP offline with Scapy, if Scapy is installed."""
    try:
        from scapy.all import IP, TCP, UDP, rdpcap
    except ImportError as exc:
        raise RuntimeError("PCAP reading requires Scapy. Install it with pip install scapy.") from exc
    packets = []
    for packet in rdpcap(source):
        if IP not in packet:
            continue
        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        flags = ""
        if TCP in packet:
            raw = int(packet[TCP].flags)
            flags = "|".join(name for bit, name in ((2, "SYN"), (16, "ACK"), (1, "FIN"), (4, "RST"), (8, "PSH")) if raw & bit)
        packets.append({
            "timestamp": float(packet.time), "src_ip": packet[IP].src, "dst_ip": packet[IP].dst,
            "src_port": int(transport.sport) if transport else 0,
            "dst_port": int(transport.dport) if transport else 0,
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else str(packet[IP].proto),
            "packet_size": len(packet), "tcp_flags": flags,
        })
    frame = pd.DataFrame(packets)
    if not frame.empty:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], unit="s")
        frame["ground_truth_attack"] = False
    return frame


def load_traffic(source: str | Path | object, filename: str | None = None) -> pd.DataFrame:
    """Dispatch an uploaded or local file to its offline reader."""
    name = filename or str(source)
    suffix = Path(name).suffix.lower()
    if suffix == ".csv":
        return load_csv(source)
    if suffix in {".pcap", ".pcapng", ".cap"}:
        return load_pcap(source)
    raise ValueError("Choose a CSV, PCAP, PCAPNG, or CAP file.")