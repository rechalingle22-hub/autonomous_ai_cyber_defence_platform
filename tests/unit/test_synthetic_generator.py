"""Unit tests for the Cyber Range Synthetic Telemetry Generator."""

import pytest
from ml.datasets.synthetic_generator import CyberRangeSyntheticGenerator


@pytest.fixture
def generator() -> CyberRangeSyntheticGenerator:
    return CyberRangeSyntheticGenerator(seed=1337)


def test_benign_traffic_generation(generator: CyberRangeSyntheticGenerator):
    """Verifies benign traffic generation produces valid structured events."""
    events = generator.generate_benign_traffic(count=50)
    assert len(events) == 50
    for ev in events:
        assert ev["label"] == "BENIGN"
        assert ev["severity"] == "INFO"
        assert ev["protocol"] in ["TCP", "UDP"]
        assert "flow_duration_ms" in ev["features"]
        assert ev["features"]["bytes_out_ratio"] <= 1.0


def test_scenario_1_brute_force(generator: CyberRangeSyntheticGenerator):
    """Verifies Scenario 1 generates repeated failed attempts followed by success."""
    events = generator.generate_scenario_1_suspicious_auth(count=20)
    assert len(events) == 20
    # Last event should be successful login
    assert events[-1]["metadata"]["auth_status"] == "SUCCESS"
    assert events[-1]["severity"] == "HIGH"
    # Prior events should be failed
    assert events[0]["metadata"]["auth_status"] == "FAILED"
    assert events[0]["features"]["failed_logins_window"] >= 1.0


def test_scenario_2_port_scan(generator: CyberRangeSyntheticGenerator):
    """Verifies Scenario 2 generates port sweep with high port entropy."""
    events = generator.generate_scenario_2_port_scan(count=40)
    assert len(events) == 40
    ports = {ev["destination_port"] for ev in events}
    assert len(ports) > 10  # Swept across many distinct ports
    assert events[0]["features"]["port_entropy"] > 0.8


def test_scenario_3_data_exfiltration(generator: CyberRangeSyntheticGenerator):
    """Verifies Scenario 3 generates massive outbound data skew."""
    events = generator.generate_scenario_3_data_exfiltration(count=15)
    assert len(events) == 15
    for ev in events:
        assert ev["features"]["bytes_out_ratio"] > 0.95
        assert ev["features"]["total_fwd_bytes"] > 1_000_000
        assert ev["label"] == "DATA_EXFILTRATION"


def test_scenario_4_compromised_account(generator: CyberRangeSyntheticGenerator):
    """Verifies Scenario 4 simulates impossible travel velocity."""
    events = generator.generate_scenario_4_compromised_account(count=10)
    assert len(events) == 10
    # First event is local
    assert events[0]["metadata"]["location"] == "New York, USA"
    # Subsequent events are from impossible foreign IP
    assert events[1]["metadata"]["location"] == "Bucharest, Romania"
    assert events[1]["label"] == "SUSPICIOUS_AUTH"


def test_scenario_5_multistage_campaign(generator: CyberRangeSyntheticGenerator):
    """Verifies Scenario 5 contains the full 4-stage attack killchain."""
    events = generator.generate_scenario_5_multistage_campaign()
    assert len(events) > 15
    stages = [ev["metadata"]["campaign_stage"] for ev in events]
    assert "RECONNAISSANCE" in stages
    assert "INITIAL_ACCESS" in stages
    assert "LATERAL_MOVEMENT" in stages
    assert "EXFILTRATION" in stages

