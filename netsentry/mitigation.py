"""Generate firewall command text only. This module never executes commands."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

RULE_LOG_PATH = Path(__file__).resolve().parents[1] / "data" / "rule_log.json"


def generate_rules(attack_type: str, source_ip: str, reason: str = "") -> dict[str, object]:
    """Build deduplicated iptables text and flag private/loopback destinations."""
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {source_ip!r}") from exc
    if not address.is_global:
        warning = f"Warning: {address} is not a globally routable address. Review this simulation rule before any use."
    else:
        warning = ""

    base = f"iptables -A INPUT -s {address} -j DROP"
    rules: list[str] = []
    if attack_type == "Port Scan":
        rules.extend([
            f"iptables -A INPUT -s {address} -m recent --name netsentry_scan --update --seconds 60 --hitcount 20 -j DROP",
            f"iptables -A INPUT -s {address} -m recent --name netsentry_scan --set -j RETURN",
        ])
    elif attack_type == "SYN Flood":
        rules.extend([
            "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT",
            "iptables -A INPUT -p tcp --syn -j DROP",
        ])
        warning = (warning + " " if warning else "") + "Consider enabling SYN cookies: sysctl net.ipv4.tcp_syncookies=1 (display only)."
    elif attack_type == "SSH Brute Force":
        rules.append(
            f"iptables -A INPUT -s {address} -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --name netsentry_ssh --update --seconds 60 --hitcount 6 -j DROP"
        )
        rules.append(
            f"iptables -A INPUT -s {address} -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --name netsentry_ssh --set -j ACCEPT"
        )
    rules.append(base)
    return {"rules": list(dict.fromkeys(rules)), "warning": warning, "source_ip": str(address)}


def log_rules(attack_type: str, reason: str, source_ip: str, rules: list[str], path: str | Path = RULE_LOG_PATH) -> dict[str, object]:
    """Append a generated-rule event to a local JSON log."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        events = json.loads(destination.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        events = []
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "attack_type": attack_type,
        "reason": reason,
        "source_ip": source_ip,
        "rules": rules,
    }
    events.append(event)
    destination.write_text(json.dumps(events[-500:], indent=2), encoding="utf-8")
    return event