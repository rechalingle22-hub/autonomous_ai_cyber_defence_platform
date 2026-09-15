# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""API integration tests for Cyber Threat Exposure & Attack Path Validation endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.exposure.engine import exposure_engine


@pytest.mark.asyncio
async def test_get_exposure_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving global threat exposure metrics."""
    resp = await async_client.get("/api/v1/exposure/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "attack_path_resilience_index" in data
    assert "total_crown_jewels" in data
    assert "total_attack_paths_discovered" in data
    assert data["total_crown_jewels"] >= 4
    assert data["attack_path_resilience_index"] >= 50.0


@pytest.mark.asyncio
async def test_list_crown_jewels_endpoint(async_client: AsyncClient):
    """Verifies listing enterprise crown jewel assets."""
    resp = await async_client.get("/api/v1/exposure/crown-jewels")
    assert resp.status_code == 200
    crown_jewels = resp.json()

    assert len(crown_jewels) >= 4
    cj_ids = [c["id"] for c in crown_jewels]
    assert "CROWN-01" in cj_ids
    assert "CROWN-02" in cj_ids


@pytest.mark.asyncio
async def test_list_attack_paths_endpoint(async_client: AsyncClient):
    """Verifies listing multi-hop attack paths."""
    resp = await async_client.get("/api/v1/exposure/attack-paths")
    assert resp.status_code == 200
    paths = resp.json()

    assert len(paths) >= 5
    first_path = paths[0]
    assert "path_id" in first_path
    assert "nodes" in first_path
    assert len(first_path["nodes"]) >= 3


@pytest.mark.asyncio
async def test_list_choke_points_endpoint(async_client: AsyncClient):
    """Verifies listing graph choke points sorted by efficiency."""
    resp = await async_client.get("/api/v1/exposure/choke-points")
    assert resp.status_code == 200
    cps = resp.json()

    assert len(cps) >= 4
    assert cps[0]["disruption_efficiency_percent"] >= cps[-1]["disruption_efficiency_percent"]


@pytest.mark.asyncio
async def test_remediate_choke_point_endpoint(async_client: AsyncClient):
    """Verifies simulating choke point remediation and audit event generation."""
    # 1. Remediate CP-01
    resp = await async_client.post(
        "/api/v1/exposure/choke-points/remediate",
        json={"choke_point_id": "CP-01"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["choke_point_id"] == "CP-01"
    assert data["severed_paths_count"] >= 1
    assert data["new_resilience_index"] > 70.0

    # 2. Unknown choke point returns 404
    resp_err = await async_client.post(
        "/api/v1/exposure/choke-points/remediate",
        json={"choke_point_id": "CP-DOES-NOT-EXIST"},
    )
    assert resp_err.status_code == 404

    # 3. Reset exposure graph
    resp_reset = await async_client.post("/api/v1/exposure/reset")
    assert resp_reset.status_code == 200
    assert resp_reset.json()["status"] == "RESET_SUCCESS"

