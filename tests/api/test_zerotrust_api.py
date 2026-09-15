# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API integration tests for Zero-Trust Adaptive Access Control & Micro-Segmentation endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.zerotrust.engine import zero_trust_engine


@pytest.mark.asyncio
async def test_get_zerotrust_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving Zero-Trust posture metrics."""
    resp = await async_client.get("/api/v1/zerotrust/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "average_trust_score" in data
    assert "active_policies_count" in data
    assert data["total_microsegmentation_policies"] >= 4
    assert data["continuous_verification_rate_percent"] == 100.0
    assert "NIST SP 800-207" in data["nist_compliance_framework"]


@pytest.mark.asyncio
async def test_evaluate_access_endpoint(async_client: AsyncClient):
    """Verifies evaluating contextual access request via API."""
    # 1. Clean compliant request
    resp = await async_client.post(
        "/api/v1/zerotrust/evaluate",
        json={
            "user_id": "test.analyst@corp.local",
            "resource_id": "api/v1/telemetry",
            "resource_sensitivity": "INTERNAL",
            "auth_level": "HARDWARE_MFA_FIDO2",
            "device_posture": {
                "edr_active": True,
                "disk_encrypted": True,
                "os_patched": True,
                "firewall_on": True,
            },
            "ueba_anomaly_score": 0.05,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"
    assert data["trust_score"] >= 85.0
    assert "score_breakdown" in data

    # 2. Blocked by micro-segmentation
    resp_block = await async_client.post(
        "/api/v1/zerotrust/evaluate",
        json={
            "user_id": "dev.user@corp.local",
            "resource_id": "production-database",
            "resource_sensitivity": "RESTRICTED_CROWN_JEWEL",
            "auth_level": "HARDWARE_MFA_FIDO2",
            "source_subnet": "10.0.10.0/24",
            "destination_subnet": "10.0.5.0/24",
        },
    )
    assert resp_block.status_code == 200
    assert resp_block.json()["decision"] == "BLOCK"


@pytest.mark.asyncio
async def test_evaluate_invalid_sensitivity(async_client: AsyncClient):
    """Verifies validation error on invalid resource sensitivity tier."""
    resp = await async_client.post(
        "/api/v1/zerotrust/evaluate",
        json={
            "user_id": "test@corp.local",
            "resource_id": "test-res",
            "resource_sensitivity": "NON_EXISTENT_TIER",
        },
    )
    assert resp.status_code == 400
    assert "Invalid resource_sensitivity" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_microsegmentation_policies_lifecycle(async_client: AsyncClient):
    """Verifies creating, listing, and toggling microsegmentation policies via API."""
    # 1. List default policies
    list_resp = await async_client.get("/api/v1/zerotrust/policies")
    assert list_resp.status_code == 200
    policies = list_resp.json()
    assert len(policies) >= 4

    # 2. Create new policy
    create_resp = await async_client.post(
        "/api/v1/zerotrust/policies",
        json={
            "name": "Integration Test Quarantine Rule",
            "source_subnet": "192.168.100.0/24",
            "destination_subnet": "10.0.0.0/8",
            "port_protocol": "ANY",
            "action": "DENY",
            "description": "Integration test rule",
        },
    )
    assert create_resp.status_code == 201
    pol_data = create_resp.json()
    pol_id = pol_data["id"]
    assert pol_data["action"] == "DENY"

    # 3. Toggle policy state
    toggle_resp = await async_client.post(f"/api/v1/zerotrust/policies/{pol_id}/toggle")
    assert toggle_resp.status_code == 200
    assert toggle_resp.json()["is_enabled"] is False


@pytest.mark.asyncio
async def test_trigger_step_up_challenge_endpoint(async_client: AsyncClient):
    """Verifies triggering a step-up MFA challenge for a session."""
    resp = await async_client.post("/api/v1/zerotrust/sessions/sess_ops_temp_02/step-up")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "CHALLENGE_PENDING"
    assert data["session_id"] == "sess_ops_temp_02"
    assert "expires_at" in data

