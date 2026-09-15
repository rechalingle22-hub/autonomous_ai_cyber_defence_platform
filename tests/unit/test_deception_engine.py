# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Cyber Deception, Honeytokens & Decoy Network Engine."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.deception.engine import (
    CyberDeceptionEngine,
    HoneytokenType,
    DecoyServiceType,
    deception_engine,
)


def test_deploy_honeytokens_across_types():
    """Verifies provisioning honeytokens across all 6 canary bait types."""
    engine = CyberDeceptionEngine()

    types = [
        HoneytokenType.API_KEY,
        HoneytokenType.DATABASE_CREDENTIAL,
        HoneytokenType.AWS_SECRET_KEY,
        HoneytokenType.JWT_TOKEN,
        HoneytokenType.CANARY_FILE,
        HoneytokenType.SSH_KEY,
    ]

    for t in types:
        token = engine.deploy_honeytoken(
            token_type=t,
            name=f"Test Decoy {t.value}",
        )
        assert token["id"].startswith(f"ht_{t.value.lower()}_")
        assert token["status"] == "ACTIVE"
        assert token["hit_count"] == 0
        assert token["token_value"] is not None
        assert "..." in token["masked_value"]
        assert len(token["bait_path"]) > 0
        assert token["id"] in engine.honeytokens


def test_trigger_honeytoken_tripwire_exact_and_mitre_mapping():
    """Verifies tripwire triggering, hit counters, and deterministic ATT&CK correlation."""
    engine = CyberDeceptionEngine()
    token = engine.deploy_honeytoken(
        token_type=HoneytokenType.AWS_SECRET_KEY,
        name="Staging AWS Cloud Root Key",
        bait_path=".env.staging",
    )

    res = engine.trigger_honeytoken_tripwire(
        token_value_or_id=token["token_value"],
        source_ip="10.0.0.99",
        user_agent="boto3/1.28.0 (Adversary Cloud Harvester)",
    )

    assert res["tripwire_triggered"] is True
    assert res["token"]["status"] == "TRIPPED"
    assert res["token"]["hit_count"] == 1
    assert res["token"]["last_attacker_ip"] == "10.0.0.99"

    alert = res["alert"]
    assert alert["severity"] == "CRITICAL"
    assert alert["fidelity"] == "100%_TRUE_POSITIVE"
    assert alert["mitre_technique_id"] == "T1078.004"
    assert "PLAYBOOK-QUARANTINE-HOST" in alert["recommended_soar_playbook"]
    assert len(engine.tripwire_events) >= 1


def test_trigger_tripwire_unrecognized_token():
    """Verifies that queries with non-existent honeytokens return cleanly with tripwire_triggered=False."""
    engine = CyberDeceptionEngine()
    res = engine.trigger_honeytoken_tripwire("invalid_token_12345")
    assert res["tripwire_triggered"] is False
    assert "error" in res


def test_revoke_honeytoken():
    """Verifies revoking active honeytoken from surveillance."""
    engine = CyberDeceptionEngine()
    token = engine.deploy_honeytoken(
        token_type=HoneytokenType.API_KEY,
        name="Temporary Partner API Token",
    )
    revoked = engine.revoke_honeytoken(token["id"])
    assert revoked is not None
    assert revoked["status"] == "REVOKED"


def test_decoy_service_interactions_and_payload_capture():
    """Verifies emulated reconnaissance interactions against decoy honeynet services."""
    engine = CyberDeceptionEngine()

    # 1. SSH Decoy
    ssh_res = engine.interact_with_decoy(
        decoy_id="decoy_ssh_01",
        command_or_payload="whoami",
        source_ip="192.168.1.205",
    )
    assert "interaction_entry" in ssh_res
    assert ssh_res["interaction_entry"]["simulated_output"] == "root"
    assert engine.decoys["decoy_ssh_01"]["status"] == "ENGAGED"
    assert engine.decoys["decoy_ssh_01"]["interaction_count"] >= 1

    # 2. Redis Decoy
    redis_res = engine.interact_with_decoy(
        decoy_id="decoy_redis_01",
        command_or_payload="KEYS *",
        source_ip="192.168.1.205",
    )
    assert "session:admin:token" in redis_res["interaction_entry"]["simulated_output"]

    # 3. SQL Decoy
    sql_res = engine.interact_with_decoy(
        decoy_id="decoy_sql_01",
        command_or_payload="SELECT * FROM users",
        source_ip="192.168.1.205",
    )
    assert "password_hash" in sql_res["interaction_entry"]["simulated_output"]


def test_get_deception_metrics_calculation():
    """Verifies global deception posture metrics computation."""
    engine = CyberDeceptionEngine()
    m = engine.get_deception_metrics()

    assert m["total_honeytokens_deployed"] >= 3
    assert m["active_honeytokens"] >= 3
    assert m["total_decoys_online"] == 4
    assert m["true_positive_fidelity_percent"] == 100.0
    assert m["zero_false_positives_guaranteed"] is True

