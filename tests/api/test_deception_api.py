# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API integration tests for Cyber Deception & Decoy Honeynet endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.deception.engine import deception_engine


@pytest.mark.asyncio
async def test_get_deception_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving deception posture metrics."""
    resp = await async_client.get("/api/v1/deception/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "total_honeytokens_deployed" in data
    assert "active_honeytokens" in data
    assert "total_decoys_online" in data
    assert data["total_decoys_online"] == 4
    assert data["true_positive_fidelity_percent"] == 100.0
    assert data["zero_false_positives_guaranteed"] is True


@pytest.mark.asyncio
async def test_list_honeytokens_endpoint(async_client: AsyncClient):
    """Verifies listing active and tripped honeytokens."""
    resp = await async_client.get("/api/v1/deception/tokens")
    assert resp.status_code == 200
    tokens = resp.json()
    assert isinstance(tokens, list)
    assert len(tokens) >= 3
    assert any(t["token_type"] == "AWS_SECRET_KEY" for t in tokens)


@pytest.mark.asyncio
async def test_deploy_and_tripwire_lifecycle_endpoint(async_client: AsyncClient):
    """Verifies deploying a new honeytoken and triggering its tripwire via REST API."""
    # 1. Deploy token
    deploy_resp = await async_client.post(
        "/api/v1/deception/tokens/deploy",
        json={
            "token_type": "JWT_TOKEN",
            "name": "Integration Test Admin JWT",
            "bait_path": "storage/test_admin.jwt",
            "metadata": {"test": True},
        },
    )
    assert deploy_resp.status_code == 201
    tok_data = deploy_resp.json()
    tok_id = tok_data["id"]
    assert tok_data["status"] == "ACTIVE"
    assert tok_data["name"] == "Integration Test Admin JWT"

    # 2. Trigger tripwire
    trip_resp = await async_client.post(
        "/api/v1/deception/tokens/tripwire",
        json={
            "token_value_or_id": tok_id,
            "source_ip": "10.0.4.15",
            "user_agent": "curl/7.88.1",
        },
    )
    assert trip_resp.status_code == 200
    trip_data = trip_resp.json()
    assert trip_data["tripwire_triggered"] is True
    assert trip_data["token"]["status"] == "TRIPPED"
    assert trip_data["alert"]["severity"] == "CRITICAL"
    assert trip_data["alert"]["fidelity"] == "100%_TRUE_POSITIVE"
    assert "T1550.001" in trip_data["alert"]["mitre_technique_id"]

    # 3. Revoke token
    revoke_resp = await async_client.post(f"/api/v1/deception/tokens/{tok_id}/revoke")
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "REVOKED"


@pytest.mark.asyncio
async def test_deploy_invalid_token_type(async_client: AsyncClient):
    """Verifies validation error on invalid honeytoken type."""
    resp = await async_client.post(
        "/api/v1/deception/tokens/deploy",
        json={
            "token_type": "INVALID_TOKEN_TYPE",
            "name": "Bad Token",
        },
    )
    assert resp.status_code == 400
    assert "Invalid token_type" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_list_and_interact_with_decoys_endpoint(async_client: AsyncClient):
    """Verifies listing decoy services and simulating adversary command probes."""
    # 1. List decoys
    list_resp = await async_client.get("/api/v1/deception/decoys")
    assert list_resp.status_code == 200
    decoys = list_resp.json()
    assert len(decoys) == 4
    ssh_decoy = next(d for d in decoys if d["id"] == "decoy_ssh_01")
    assert ssh_decoy["port"] == 2222

    # 2. Interact with decoy
    probe_resp = await async_client.post(
        "/api/v1/deception/decoys/decoy_ssh_01/interact",
        json={
            "command_or_payload": "cat /etc/passwd",
            "source_ip": "172.16.0.45",
        },
    )
    assert probe_resp.status_code == 200
    probe_data = probe_resp.json()
    assert "interaction_entry" in probe_data
    assert "root:x:0:0" in probe_data["interaction_entry"]["simulated_output"]

