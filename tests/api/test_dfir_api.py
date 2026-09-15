# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API integration tests for DFIR Evidence Locker & Custody endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.dfir.engine import dfir_engine


@pytest.mark.asyncio
async def test_get_dfir_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving DFIR evidence locker metrics."""
    resp = await async_client.get("/api/v1/dfir/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "total_artifacts" in data
    assert "verified_integrity_rate_percent" in data
    assert data["total_artifacts"] >= 3
    assert data["verified_integrity_rate_percent"] == 100.0


@pytest.mark.asyncio
async def test_list_cases_endpoint(async_client: AsyncClient):
    """Verifies retrieving active forensic cases."""
    resp = await async_client.get("/api/v1/dfir/cases")
    assert resp.status_code == 200
    cases = resp.json()

    assert len(cases) >= 1
    assert cases[0]["case_id"] == "CASE-2024-001"


@pytest.mark.asyncio
async def test_acquire_artifact_endpoint(async_client: AsyncClient):
    """Verifies acquiring and cryptographically sealing a forensic artifact via API."""
    # 1. Valid acquisition
    resp = await async_client.post(
        "/api/v1/dfir/artifacts/acquire",
        json={
            "case_id": "CASE-2024-001",
            "artifact_name": "kernel_crash_triage.dmp",
            "artifact_type": "VOLATILE_MEMORY",
            "affected_host": "db-server-prod-01",
            "source_path": "/var/crash/vmcore-triage.img",
            "content_text": "KERNEL_CRASH_DUMP_VOLATILE_PAYLOAD_TEST",
            "acquired_by": "Special Agent Lin",
            "notes": "Acquired during active incident investigation",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["artifact_name"] == "kernel_crash_triage.dmp"
    assert len(data["genesis_sha256"]) == 64
    assert len(data["genesis_sha3_512"]) == 128
    assert data["is_tamper_detected"] is False

    # 2. Invalid artifact type returns 400
    resp_bad = await async_client.post(
        "/api/v1/dfir/artifacts/acquire",
        json={
            "case_id": "CASE-2024-001",
            "artifact_name": "bad.raw",
            "artifact_type": "INVALID_TYPE_XYZ",
            "affected_host": "db",
            "content_text": "data",
            "acquired_by": "Agent",
        },
    )
    assert resp_bad.status_code == 400


@pytest.mark.asyncio
async def test_list_and_filter_artifacts_endpoint(async_client: AsyncClient):
    """Verifies listing artifacts and applying filters."""
    # List all
    resp_all = await async_client.get("/api/v1/dfir/artifacts")
    assert resp_all.status_code == 200
    artifacts = resp_all.json()
    assert len(artifacts) >= 3

    # Filter by artifact_type
    resp_pcap = await async_client.get("/api/v1/dfir/artifacts?artifact_type=NETWORK_PCAP")
    assert resp_pcap.status_code == 200
    for a in resp_pcap.json():
        assert a["artifact_type"] == "NETWORK_PCAP"


@pytest.mark.asyncio
async def test_verify_artifact_integrity_endpoint(async_client: AsyncClient):
    """Verifies cryptographic re-verification endpoint."""
    art_id = list(dfir_engine.artifacts.keys())[0]

    # Untampered verification
    resp = await async_client.post(f"/api/v1/dfir/artifacts/{art_id}/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["integrity_verified"] is True
    assert data["tamper_detected"] is False

    # Unknown artifact returns 404
    resp_404 = await async_client.post("/api/v1/dfir/artifacts/evid-nonexistent-999/verify")
    assert resp_404.status_code == 404


@pytest.mark.asyncio
async def test_transfer_custody_and_certificate_endpoint(async_client: AsyncClient):
    """Verifies custody transfer and exporting court-admissible certificate."""
    art_id = list(dfir_engine.artifacts.keys())[0]

    # Transfer custody
    resp_xfer = await async_client.post(
        f"/api/v1/dfir/artifacts/{art_id}/transfer",
        json={
            "new_custodian": "Prosecutor Forensic Vault Unit B",
            "purpose": "Evidence submission for judicial discovery",
        },
    )
    assert resp_xfer.status_code == 200
    xfer_data = resp_xfer.json()
    assert xfer_data["current_custodian"] == "Prosecutor Forensic Vault Unit B"

    # Export custody certificate
    resp_cert = await async_client.get("/api/v1/dfir/cases/CASE-2024-001/certificate")
    assert resp_cert.status_code == 200
    cert = resp_cert.json()
    assert cert["admissibility_status"] == "COURT_ADMISSIBLE_VERIFIED"
    assert "merkle_root_hash" in cert
    assert cert["total_artifacts_certified"] >= 3

