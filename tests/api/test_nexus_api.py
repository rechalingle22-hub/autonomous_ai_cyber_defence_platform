# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""API integration tests for Master SOC Command Nexus endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.nexus.engine import nexus_engine


@pytest.mark.asyncio
async def test_get_master_posture_endpoint(async_client: AsyncClient):
    """Verifies retrieving global platform posture and 24-engine heartbeat."""
    resp = await async_client.get("/api/v1/nexus/posture")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_subsystems"] == 24
    assert data["online_subsystems"] == 24
    assert data["defense_readiness_index"] >= 98.0
    assert data["automated_containment_rate"] >= 95.0
    assert len(data["subsystems"]) == 24


@pytest.mark.asyncio
async def test_emergency_lockdown_api_lifecycle(async_client: AsyncClient):
    """Verifies triggering and lifting lockdown via REST API."""
    # 1. Trigger lockdown
    resp_lck = await async_client.post(
        "/api/v1/nexus/emergency-lockdown",
        json={
            "operator": "LEAD_INCIDENT_COMMANDER",
            "reason": "SIMULATED_EXFILTRATION_TEST",
        },
    )
    assert resp_lck.status_code == 200
    lck_data = resp_lck.json()
    assert lck_data["status"] == "SUCCESS"
    assert lck_data["is_lockdown_active"] is True
    assert "lockdown_id" in lck_data

    # 2. Verify posture reflects lockdown
    resp_posture = await async_client.get("/api/v1/nexus/posture")
    assert resp_posture.status_code == 200
    assert resp_posture.json()["is_lockdown_active"] is True

    # 3. Lift lockdown
    resp_lift = await async_client.post("/api/v1/nexus/lift-lockdown")
    assert resp_lift.status_code == 200
    assert resp_lift.json()["status"] == "SUCCESS"

    # 4. Verify restored posture
    resp_restored = await async_client.get("/api/v1/nexus/posture")
    assert resp_restored.status_code == 200
    assert resp_restored.json()["is_lockdown_active"] is False


@pytest.mark.asyncio
async def test_run_diagnostics_endpoint(async_client: AsyncClient):
    """Verifies running self-healing diagnostic probe across all 24 engines."""
    resp = await async_client.post("/api/v1/nexus/run-diagnostics")
    assert resp.status_code == 200
    diag = resp.json()

    assert diag["platform_certification"] == "ALL_24_ENGINES_CERTIFIED_OPERATIONAL"
    assert diag["total_checks_passed"] == 24
    assert diag["total_checks_failed"] == 0
    assert diag["ai_defense_score"] == 100.0
    assert len(diag["engine_results"]) == 24

