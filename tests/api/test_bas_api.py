# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""API integration tests for Breach and Attack Simulation (BAS) endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.bas.engine import bas_engine


@pytest.mark.asyncio
async def test_get_bas_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving global BAS posture metrics."""
    resp = await async_client.get("/api/v1/bas/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "overall_posture_score" in data
    assert "detection_rate_percent" in data
    assert "prevention_rate_percent" in data
    assert "mitre_techniques_covered" in data
    assert data["total_campaigns_available"] >= 4
    assert data["overall_posture_score"] > 0


@pytest.mark.asyncio
async def test_list_and_get_campaigns_endpoint(async_client: AsyncClient):
    """Verifies listing curated adversary campaigns and fetching single profile."""
    resp = await async_client.get("/api/v1/bas/campaigns")
    assert resp.status_code == 200
    campaigns = resp.json()

    assert len(campaigns) >= 4
    c_ids = [c["campaign_id"] for c in campaigns]
    assert "APT29" in c_ids

    # Fetch APT29 profile
    resp_apt = await async_client.get("/api/v1/bas/campaigns/APT29")
    assert resp_apt.status_code == 200
    apt_data = resp_apt.json()
    assert apt_data["campaign_id"] == "APT29"
    assert len(apt_data["stages"]) == 8

    # Unknown campaign returns 404
    resp_bad = await async_client.get("/api/v1/bas/campaigns/UNKNOWN_CAMPAIGN_123")
    assert resp_bad.status_code == 404


@pytest.mark.asyncio
async def test_execute_campaign_endpoint(async_client: AsyncClient):
    """Verifies triggering an automated adversary simulation run and audit log creation."""
    resp = await async_client.post(
        "/api/v1/bas/campaigns/execute",
        json={
            "campaign_id": "APT29",
            "target_environment": "Automated Range Test Environment",
            "dry_run": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["campaign_id"] == "APT29"
    assert data["total_stages"] == 8
    assert data["posture_score"] >= 70.0
    assert len(data["stage_results"]) == 8
    assert data["summary_verdict"] in ("STRONG_RESILIENCE", "MODERATE_RESILIENCE")

    # Invalid campaign returns 404
    resp_err = await async_client.post(
        "/api/v1/bas/campaigns/execute",
        json={"campaign_id": "NON_EXISTENT_APT"},
    )
    assert resp_err.status_code == 404


@pytest.mark.asyncio
async def test_get_simulations_history_endpoint(async_client: AsyncClient):
    """Verifies retrieving adversary simulation run history."""
    resp = await async_client.get("/api/v1/bas/simulations?limit=10")
    assert resp.status_code == 200
    sims = resp.json()

    assert len(sims) >= 1
    assert "simulation_id" in sims[0]
    assert "posture_score" in sims[0]


@pytest.mark.asyncio
async def test_get_coverage_matrix_endpoint(async_client: AsyncClient):
    """Verifies retrieving the MITRE ATT&CK coverage matrix."""
    resp = await async_client.get("/api/v1/bas/coverage-matrix")
    assert resp.status_code == 200
    matrix = resp.json()

    assert len(matrix) >= 20
    first_item = matrix[0]
    assert "technique_id" in first_item
    assert "tactic" in first_item
    assert "status" in first_item
    assert "detecting_layer" in first_item

