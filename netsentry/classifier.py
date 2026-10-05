"""Explain anomalous windows with transparent behavior-based rules."""

from __future__ import annotations

from typing import Any


def classify_attack(features: dict[str, Any]) -> dict[str, str]:
    """Return an attack label, severity, and beginner-friendly explanation."""
    rate = float(features.get("packet_rate", 0))
    syn_ratio = float(features.get("syn_ack_ratio", 0))
    unique_ports = int(features.get("unique_dst_ports", 0))
    source_count = int(features.get("unique_src_ips", 0))
    top_share = float(features.get("top_source_share", 0))
    ssh_share = float(features.get("ssh_share", 0))

    if rate >= 500 and syn_ratio >= 5:
        attack_type, severity = "SYN Flood", "Critical"
        reason = "Many SYN packets are arriving quickly with almost no replies, which looks like a SYN flood."
    elif unique_ports >= 35 and top_share >= 0.30:
        attack_type, severity = "Port Scan", "High"
        reason = f"One source is probing {unique_ports} destination ports in a short time, which looks like a port scan."
    elif ssh_share >= 0.55 and source_count <= 8:
        attack_type, severity = "SSH Brute Force", "High"
        reason = "Repeated short connections to SSH (port 22) suggest someone is guessing login credentials."
    elif rate >= 500 and source_count >= 15:
        attack_type, severity = "DDoS (volumetric)", "Critical"
        reason = "A very high packet rate from many sources may overwhelm the server."
    else:
        attack_type, severity = "Unknown anomaly", "Medium"
        reason = "Traffic behavior is unusual compared with the learned normal pattern."
    return {"attack_type": attack_type, "severity": severity, "reason": reason}