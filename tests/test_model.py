from netsentry.classifier import classify_attack
from netsentry.features import extract_features
from netsentry.model import AnomalyDetector
from netsentry.simulator import generate_traffic


def test_syn_flood_scores_as_anomaly_with_few_normal_false_positives():
    training = extract_features(generate_traffic(180, "normal", seed=91))
    detector = AnomalyDetector().fit(training)
    normal = extract_features(generate_traffic(40, "normal", seed=910))
    flood = extract_features(generate_traffic(3, "syn_flood", seed=911))
    assert detector.predict(flood)["is_anomaly"].mean() >= 0.8
    assert detector.predict(normal)["is_anomaly"].mean() <= 0.15


def test_attack_scenarios_receive_expected_explanations():
    expected = {"syn_flood": "SYN Flood", "port_scan": "Port Scan", "ssh_brute_force": "SSH Brute Force"}
    for scenario, attack_type in expected.items():
        window = extract_features(generate_traffic(1, scenario, seed=12)).iloc[0]
        assert classify_attack(window.to_dict())["attack_type"] == attack_type


def test_detector_flags_port_scan_and_ssh_brute_force():
    training = extract_features(generate_traffic(180, "normal", seed=91))
    detector = AnomalyDetector().fit(training)
    for scenario, attack_type in (("port_scan", "Port Scan"), ("ssh_brute_force", "SSH Brute Force")):
        features = extract_features(generate_traffic(3, scenario, seed=12))
        assert detector.predict(features)["is_anomaly"].all()
        assert classify_attack(features.iloc[0].to_dict())["attack_type"] == attack_type