"""Create reproducible synthetic packet traffic; no packets are transmitted."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterator

import numpy as np
import pandas as pd

PACKET_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "packet_size", "tcp_flags",
]
SCENARIOS = ("normal", "syn_flood", "port_scan", "ssh_brute_force", "mixed")
TARGET_IP = "192.0.2.10"
SCAN_IP = "198.51.100.42"


def _ip(rng: np.random.Generator, prefix: str) -> str:
    return f"{prefix}.{int(rng.integers(1, 255))}"


def _packet(
    rng: np.random.Generator,
    timestamp: datetime,
    scenario: str,
    index: int,
) -> dict[str, object]:
    """Build one packet record and its synthetic ground-truth labels."""
    attack = scenario != "normal"
    if scenario == "normal":
        src_ip = _ip(rng, "203.0.113")
        dst_port = int(rng.choice([80, 443, 53], p=[0.48, 0.46, 0.06]))
        protocol = "UDP" if dst_port == 53 else "TCP"
        tcp_flags = str(rng.choice(["SYN", "ACK", "PSH", "FIN", "SYN-ACK"], p=[0.22, 0.28, 0.30, 0.08, 0.12])) if protocol == "TCP" else ""
        size = int(rng.integers(64, 1450))
    elif scenario == "syn_flood":
        src_ip = _ip(rng, "198.51.100")
        dst_port, protocol, tcp_flags, size = 443, "TCP", "SYN", 60
        if index % 80 == 0:
            tcp_flags = "ACK"
    elif scenario == "port_scan":
        src_ip = SCAN_IP
        dst_port = int((index % 65534) + 1)
        protocol, tcp_flags, size = "TCP", "SYN", 60
    else:
        src_ip = f"198.51.100.{77 + index % 3}"
        dst_port, protocol = 22, "TCP"
        tcp_flags = "SYN" if index % 3 else "RST"
        size = int(rng.integers(60, 100))

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": TARGET_IP if attack else _ip(rng, "192.0"),
        "src_port": int(rng.integers(1024, 65536)),
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_size": size,
        "tcp_flags": tcp_flags,
        "ground_truth_attack": attack,
        "ground_truth_type": scenario if attack else "Normal",
    }


def generate_traffic(
    duration_seconds: int = 60,
    scenario: str = "normal",
    seed: int = 42,
    start_time: datetime | None = None,
) -> pd.DataFrame:
    """Generate a labeled, per-packet DataFrame for a named scenario."""
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario {scenario!r}; choose from {', '.join(SCENARIOS)}")
    if duration_seconds < 1:
        raise ValueError("duration_seconds must be at least 1")

    rng = np.random.default_rng(seed)
    start = start_time or datetime(2025, 1, 1)
    rows: list[dict[str, object]] = []
    scan_index = 0
    for second in range(duration_seconds):
        active = scenario
        if scenario == "mixed":
            # Reproducible attack bursts interleaved with ordinary traffic.
            cycle = second % 15
            active = "normal" if cycle < 8 else ("syn_flood" if cycle < 11 else "port_scan" if cycle < 13 else "ssh_brute_force")
        if active == "normal":
            count = int(rng.integers(35, 90))
        elif active == "syn_flood":
            count = int(rng.integers(1100, 1600))
        elif active == "port_scan":
            count = int(rng.integers(180, 280))
        else:
            count = int(rng.integers(180, 280))
        for index in range(count):
            packet_time = start + timedelta(seconds=second, microseconds=int(rng.integers(0, 1_000_000)))
            packet_index = scan_index if active == "port_scan" else index
            rows.append(_packet(rng, packet_time, active, packet_index))
            if active == "port_scan":
                scan_index += 1
    return pd.DataFrame.from_records(rows)


def live_batches(
    scenario: str = "normal",
    seed: int = 42,
    start_time: datetime | None = None,
) -> Iterator[pd.DataFrame]:
    """Yield one simulated second at a time for live dashboard playback."""
    start = start_time or datetime.now().replace(microsecond=0)
    for tick in range(1_000_000):
        yield generate_traffic(1, scenario, seed + tick, start + timedelta(seconds=tick))