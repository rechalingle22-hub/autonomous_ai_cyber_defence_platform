# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for DFIR Evidence Locker & Cryptographic Custody Engine."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.dfir.engine import (
    DfirEngine,
    ArtifactType,
    CustodyAction,
    dfir_engine,
)


def test_default_cases_and_artifacts():
    """Verifies default forensic cases and pre-seeded court-admissible artifacts."""
    engine = DfirEngine()
    assert len(engine.cases) >= 1
    assert len(engine.artifacts) >= 3

    case = engine.cases["CASE-2024-001"]
    assert case["lead_examiner"] is not None
    assert case["evidence_count"] >= 3


def test_acquire_artifact_dual_hashing():
    """Verifies artifact acquisition generates valid SHA-256 and SHA3-512 hashes."""
    engine = DfirEngine()
    test_bytes = b"VOLATILE_REGISTRY_HIVE_PAYLOAD_SYSTEM_CONTROLSET001"

    artifact = engine.acquire_artifact(
        case_id="CASE-2024-001",
        artifact_name="system_hive_dump.raw",
        artifact_type=ArtifactType.TRIAGE_BUNDLE,
        affected_host="workstation-409.internal",
        source_path="/Windows/System32/config/SYSTEM",
        raw_content=test_bytes,
        acquired_by="Forensic Agent Marcus Reed",
        notes="Extracted registry hive during live incident response",
    )

    assert artifact["id"] in engine.artifacts
    assert len(artifact["genesis_sha256"]) == 64
    assert len(artifact["genesis_sha3_512"]) == 128
    assert artifact["file_size_bytes"] == len(test_bytes)
    assert artifact["current_custodian"] == "Forensic Agent Marcus Reed"
    assert artifact["is_tamper_detected"] is False

    # Verify initial accession event was added to Merkle ledger
    latest_event = engine.custody_ledger[-1]
    assert latest_event["artifact_id"] == artifact["id"]
    assert latest_event["action"] == CustodyAction.ACCESSION_SEALED.value
    assert len(latest_event["leaf_hash"]) == 64


def test_integrity_verification_untampered():
    """Verifies that an untouched artifact passes cryptographic re-verification."""
    engine = DfirEngine()
    test_artifact_id = list(engine.artifacts.keys())[0]

    result = engine.verify_artifact_integrity(test_artifact_id)

    assert result["integrity_verified"] is True
    assert result["tamper_detected"] is False
    assert result["current_sha256"] == result["genesis_sha256"]
    assert result["current_sha3_512"] == result["genesis_sha3_512"]


def test_integrity_verification_tamper_detection():
    """Verifies that bit-level modification immediately triggers tamper detection."""
    engine = DfirEngine()
    test_artifact_id = list(engine.artifacts.keys())[0]

    # Re-verify with simulated bit-level tampering
    tampered_result = engine.verify_artifact_integrity(test_artifact_id, tamper_with_byte=True)

    assert tampered_result["integrity_verified"] is False
    assert tampered_result["tamper_detected"] is True
    assert tampered_result["current_sha256"] != tampered_result["genesis_sha256"]
    assert engine.artifacts[test_artifact_id]["is_tamper_detected"] is True


def test_transfer_custody():
    """Verifies transferring evidence custody records an immutable audit ledger entry."""
    engine = DfirEngine()
    test_artifact_id = list(engine.artifacts.keys())[0]
    initial_chain_len = engine.artifacts[test_artifact_id]["custody_chain_length"]

    updated = engine.transfer_custody(
        artifact_id=test_artifact_id,
        new_custodian="Federal Evidence Vault Custodian Officer Kelly",
        purpose="Escrow deposition for grand jury presentation",
    )

    assert updated["current_custodian"] == "Federal Evidence Vault Custodian Officer Kelly"
    assert updated["custody_chain_length"] > initial_chain_len

    latest_custody = engine.custody_ledger[-1]
    assert latest_custody["action"] == CustodyAction.CUSTODY_TRANSFERRED.value
    assert latest_custody["custodian"] == "Federal Evidence Vault Custodian Officer Kelly"


def test_generate_custody_certificate():
    """Verifies generating court-admissible certificate with Merkle root hash."""
    engine = DfirEngine()
    cert = engine.generate_custody_certificate("CASE-2024-001")

    assert cert["case_id"] == "CASE-2024-001"
    assert cert["admissibility_status"] == "COURT_ADMISSIBLE_VERIFIED"
    assert len(cert["merkle_root_hash"]) == 64
    assert cert["total_artifacts_certified"] >= 3
    assert cert["total_custody_events"] >= 3
    assert "ISO/IEC 27037" in cert["standard_compliance"]


def test_dfir_metrics():
    """Verifies aggregated forensic posture metrics."""
    engine = DfirEngine()
    metrics = engine.get_metrics()

    assert metrics["total_artifacts"] >= 3
    assert metrics["total_cases"] >= 1
    assert metrics["total_evidence_size_bytes"] > 0
    assert metrics["verified_integrity_rate_percent"] == 100.0
    assert metrics["tamper_incidents_detected"] == 0
    assert metrics["total_custody_events"] >= 3

