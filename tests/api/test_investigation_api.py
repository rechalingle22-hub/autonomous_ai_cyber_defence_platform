# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API Integration tests for Multi-Agent AI SOC Investigation Endpoints."""

import os
import sys
import uuid
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


@pytest.mark.asyncio
async def test_trigger_investigation_endpoint(async_client: AsyncClient):
    """Verifies triggering multi-agent investigation on an incident."""
    payload = {
        "incident_id": f"INC-AUTO-{uuid.uuid4().hex[:6]}",
        "analyst_id": "analyst_bob",
        "priority": "HIGH",
        "notes": "Triggered from API test",
    }

    resp = await async_client.post("/api/v1/investigations/trigger", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert data["incident_id"] == payload["incident_id"]
    assert data["status"] == "COMPLETED"
    assert data["analyst_id"] == "analyst_bob"
    assert "id" in data
    assert "executive_summary" in data
    assert "technical_analysis" in data
    assert data["executive_summary"] is not None
    assert "observed_evidence" in data
    assert "inferred_hypotheses" in data


@pytest.mark.asyncio
async def test_list_investigations_endpoint(async_client: AsyncClient):
    """Verifies listing active and historical investigations."""
    await async_client.post(
        "/api/v1/investigations/trigger",
        json={"incident_id": f"INC-LIST-{uuid.uuid4().hex[:6]}"},
    )
    resp = await async_client.get("/api/v1/investigations")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


@pytest.mark.asyncio
async def test_get_investigation_by_id_and_not_found(async_client: AsyncClient):
    """Verifies retrieval by ID and 404 handling."""
    # 1. Trigger fresh investigation
    payload = {"incident_id": f"INC-GET-{uuid.uuid4().hex[:6]}"}
    create_resp = await async_client.post("/api/v1/investigations/trigger", json=payload)
    assert create_resp.status_code == 201
    inv_id = create_resp.json()["id"]

    # 2. Get by valid ID
    get_resp = await async_client.get(f"/api/v1/investigations/{inv_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == inv_id

    # 3. Get non-existent
    bad_resp = await async_client.get("/api/v1/investigations/non-existent-inv-999")
    assert bad_resp.status_code == 404


@pytest.mark.asyncio
async def test_add_analyst_hypothesis_endpoint(async_client: AsyncClient):
    """Verifies adding a human analyst hypothesis into an ongoing case dossier."""
    # 1. Trigger investigation
    init_resp = await async_client.post(
        "/api/v1/investigations/trigger",
        json={"incident_id": f"INC-HYP-{uuid.uuid4().hex[:6]}"},
    )
    assert init_resp.status_code == 201
    inv_id = init_resp.json()["id"]

    # 2. Add analyst hypothesis
    hyp_payload = {
        "claim": "Analyst manual assessment: Credential stuffing pattern from commercial proxy.",
        "supporting_evidence_ids": [],
        "confidence": 0.92,
        "risk_level": "HIGH",
        "recommended_action": "Enable mandatory MFA challenge on target account.",
    }
    hyp_resp = await async_client.post(f"/api/v1/investigations/{inv_id}/hypothesize", json=hyp_payload)
    assert hyp_resp.status_code == 200
    data = hyp_resp.json()

    hypotheses = data["inferred_hypotheses"].get("items", [])
    assert any("Credential stuffing" in h.get("claim", "") for h in hypotheses)


@pytest.mark.asyncio
async def test_investigation_stats_overview(async_client: AsyncClient):
    """Verifies operational investigation telemetry metrics."""
    resp = await async_client.get("/api/v1/investigations/stats/overview")
    assert resp.status_code == 200
    stats = resp.json()
    assert "total_investigations" in stats
    assert "completed_count" in stats
    assert stats["total_investigations"] >= 1
    assert stats["completed_count"] >= 1
