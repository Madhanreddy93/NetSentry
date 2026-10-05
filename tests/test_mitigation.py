import pytest

from netsentry.mitigation import generate_rules


def test_syn_rules_are_text_and_include_safety_note():
    result = generate_rules("SYN Flood", "198.51.100.8", "test")
    assert any("--syn -m limit" in rule for rule in result["rules"])
    assert any("--syn -j DROP" in rule for rule in result["rules"])
    assert "SYN cookies" in result["warning"]
    assert len(result["rules"]) == len(set(result["rules"]))


def test_private_ip_is_flagged_and_invalid_ip_rejected():
    assert "Warning" in generate_rules("Port Scan", "127.0.0.1")["warning"]
    with pytest.raises(ValueError):
        generate_rules("Port Scan", "not-an-ip")


def test_ssh_and_scan_rules_are_attack_specific():
    ssh = generate_rules("SSH Brute Force", "203.0.113.7")["rules"]
    scan = generate_rules("Port Scan", "203.0.113.7")["rules"]
    assert any("--dport 22" in rule for rule in ssh)
    assert any("--name netsentry_scan" in rule for rule in scan)
    assert ssh.index(next(rule for rule in ssh if "--dport 22" in rule)) < len(ssh) - 1
    assert scan.index(next(rule for rule in scan if "--name netsentry_scan" in rule)) < len(scan) - 1