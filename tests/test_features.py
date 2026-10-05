from netsentry.features import extract_features
from netsentry.simulator import generate_traffic


def test_features_include_rates_flags_entropy_and_context():
    packets = generate_traffic(3, "normal", seed=12)
    features = extract_features(packets, window_seconds=1)
    assert len(features) == 3
    assert (features["packet_rate"] > 0).all()
    assert features["syn_ack_ratio"].notna().all()
    assert features["protocol_entropy"].between(0, 1).all()
    assert (features["unique_src_ips"] >= 1).all()


def test_empty_traffic_returns_clean_empty_frame():
    result = extract_features(generate_traffic(1).iloc[0:0])
    assert result.empty
    assert "packet_rate" in result.columns