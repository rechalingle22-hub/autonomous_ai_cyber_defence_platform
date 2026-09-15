# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Zero-Trust Adaptive Access Control & Micro-Segmentation Engine."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.zerotrust.engine import (
    ZeroTrustEngine,
    AccessDecision,
    ResourceSensitivity,
    AuthAssuranceLevel,
    zero_trust_engine,
)


def test_trust_score_optimal_posture():
    """Verifies trust score calculation under optimal security conditions."""
    engine = ZeroTrustEngine()
    score_data = engine.calculate_trust_score(
        auth_level=AuthAssuranceLevel.HARDWARE_MFA_FIDO2,
        device_posture={
            "edr_active": True,
            "disk_encrypted": True,
            "os_patched": True,
            "firewall_on": True,
        },
        ueba_anomaly_score=0.0,
        network_context={"is_vpn_or_tor": False, "threat_reputation_score": 0.0},
        active_incident_link=False,
    )

    assert score_data["trust_score"] == 100.0
    assert score_data["breakdown"]["authentication_score"] == 100.0
    assert score_data["breakdown"]["device_posture_score"] == 100.0
    assert score_data["breakdown"]["behavioral_trust_score"] == 100.0


def test_trust_score_degraded_posture():
    """Verifies score degradation when single-factor auth, unencrypted disk, and anomaly occur."""
    engine = ZeroTrustEngine()
    score_data = engine.calculate_trust_score(
        auth_level=AuthAssuranceLevel.PASSWORD_ONLY,
        device_posture={
            "edr_active": False,
            "disk_encrypted": False,
            "os_patched": False,
            "firewall_on": True,
        },
        ueba_anomaly_score=0.8,
        network_context={"is_vpn_or_tor": True, "threat_reputation_score": 40.0},
        active_incident_link=True,
    )

    # Trust score should fall dramatically
    assert score_data["trust_score"] < 40.0
    assert score_data["breakdown"]["authentication_score"] == 35.0
    assert score_data["breakdown"]["device_posture_score"] == 15.0


def test_evaluate_access_allow_vs_step_up_vs_block():
    """Verifies NIST SP 800-207 decision matrix across sensitivity tiers."""
    engine = ZeroTrustEngine()

    # 1. High trust -> ALLOW on INTERNAL
    res_allow = engine.evaluate_access_request(
        user_id="alice@corp.local",
        resource_id="internal-jira.corp.local",
        resource_sensitivity=ResourceSensitivity.INTERNAL,
        auth_level=AuthAssuranceLevel.HARDWARE_MFA_FIDO2,
        device_posture={"edr_active": True, "disk_encrypted": True, "os_patched": True, "firewall_on": True},
    )
    assert res_allow["decision"] == AccessDecision.ALLOW.value
    assert res_allow["trust_score"] >= 90.0

    # 2. Moderate trust on RESTRICTED_CROWN_JEWEL -> STEP_UP_AUTH
    res_stepup = engine.evaluate_access_request(
        user_id="bob@corp.local",
        resource_id="payment-vault.corp.local",
        resource_sensitivity=ResourceSensitivity.RESTRICTED_CROWN_JEWEL,
        auth_level=AuthAssuranceLevel.PASSWORD_SMS,
        device_posture={"edr_active": True, "disk_encrypted": True, "os_patched": True, "firewall_on": True},
    )
    assert res_stepup["decision"] in (AccessDecision.STEP_UP_AUTH.value, AccessDecision.RESTRICT.value)

    # 3. Critical low trust -> BLOCK
    res_block = engine.evaluate_access_request(
        user_id="mallory@adversary.com",
        resource_id="customer-db.corp.local",
        resource_sensitivity=ResourceSensitivity.CONFIDENTIAL,
        auth_level=AuthAssuranceLevel.PASSWORD_ONLY,
        device_posture={"edr_active": False, "disk_encrypted": False, "os_patched": False, "firewall_on": False},
        ueba_anomaly_score=0.95,
        active_incident_link=True,
    )
    assert res_block["decision"] == AccessDecision.BLOCK.value


def test_microsegmentation_lateral_movement_block():
    """Verifies micro-segmentation rule automatically forces BLOCK regardless of trust score."""
    engine = ZeroTrustEngine()

    # Even with 100% trust score, moving from developer subnet to production db is blocked by rule
    res = engine.evaluate_access_request(
        user_id="admin@corp.local",
        resource_id="prod-db-cluster",
        resource_sensitivity=ResourceSensitivity.RESTRICTED_CROWN_JEWEL,
        auth_level=AuthAssuranceLevel.HARDWARE_MFA_FIDO2,
        source_subnet="10.0.10.0/24",
        destination_subnet="10.0.5.0/24",
    )
    assert res["decision"] == AccessDecision.BLOCK.value
    assert "micro-segmentation" in res["reason"].lower()


def test_create_and_toggle_microsegmentation_policy():
    """Verifies provisioning new policy and toggling its enforcement state."""
    engine = ZeroTrustEngine()

    policy = engine.create_microsegmentation_policy(
        name="Quarantine Subnet Route",
        source_subnet="10.0.99.0/24",
        destination_subnet="10.0.0.0/8",
        port_protocol="ANY",
        action="DENY",
        description="Isolates infected host subnet",
    )
    assert policy["id"] in engine.microsegmentation_policies
    assert policy["is_enabled"] is True

    toggled = engine.toggle_policy(policy["id"])
    assert toggled is not None
    assert toggled["is_enabled"] is False

    toggled_again = engine.toggle_policy(policy["id"])
    assert toggled_again["is_enabled"] is True


def test_trigger_step_up_challenge():
    """Verifies step-up challenge creation and session status transition."""
    engine = ZeroTrustEngine()
    chal = engine.trigger_step_up_challenge("sess_ops_temp_02")

    assert chal["status"] == "CHALLENGE_PENDING"
    assert chal["session_id"] == "sess_ops_temp_02"
    assert "sess_ops_temp_02" in engine.sessions
    assert engine.sessions["sess_ops_temp_02"]["status"] == "CHALLENGED"


def test_get_zero_trust_metrics():
    """Verifies metrics aggregation for Zero-Trust posture."""
    engine = ZeroTrustEngine()
    m = engine.get_zero_trust_metrics()

    assert "average_trust_score" in m
    assert "active_policies_count" in m
    assert m["total_microsegmentation_policies"] >= 4
    assert m["continuous_verification_rate_percent"] == 100.0
    assert m["nist_compliance_framework"] == "NIST SP 800-207"

