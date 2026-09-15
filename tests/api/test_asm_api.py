# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API integration tests for Attack Surface Management & RBVM endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.asm.engine import asm_engine


@pytest.mark.asyncio
async def test_get_asm_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving Attack Surface exposure metrics."""
    resp = await async_client.get("/api/v1/asm/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "attack_surface_exposure_score" in data
    assert "total_assets" in data
    assert "internet_facing_assets" in data
    assert data["total_assets"] >= 5
    assert data["total_vulnerabilities"] >= 5
    assert data["sla_compliance_rate"] >= 90.0


@pytest.mark.asyncio
async def test_list_assets_and_filtering(async_client: AsyncClient):
    """Verifies listing discovered assets and filtering by exposure level."""
    # List all assets
    resp_all = await async_client.get("/api/v1/asm/assets")
    assert resp_all.status_code == 200
    assets = resp_all.json()
    assert len(assets) >= 5

    # Filter by INTERNET_FACING
    resp_filtered = await async_client.get("/api/v1/asm/assets?exposure=INTERNET_FACING")
    assert resp_filtered.status_code == 200
    filtered_assets = resp_filtered.json()
    for a in filtered_assets:
        assert a["exposure"] == "INTERNET_FACING"

    # Invalid exposure filter returns 400
    resp_bad = await async_client.get("/api/v1/asm/assets?exposure=INVALID_TIER")
    assert resp_bad.status_code == 400


@pytest.mark.asyncio
async def test_trigger_asm_scan_endpoint(async_client: AsyncClient):
    """Verifies triggering an active threat surface discovery scan."""
    resp = await async_client.post(
        "/api/v1/asm/assets/scan",
        json={
            "subnet_range": "198.51.100.0/24",
            "scan_intensity": "COMPREHENSIVE",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["subnet_range"] == "198.51.100.0/24"
    assert data["assets_discovered"] >= 1
    assert "scan_id" in data


@pytest.mark.asyncio
async def test_list_and_filter_vulnerabilities(async_client: AsyncClient):
    """Verifies listing vulnerabilities and filtering by status and priority."""
    resp = await async_client.get("/api/v1/asm/vulnerabilities")
    assert resp.status_code == 200
    vulns = resp.json()
    assert len(vulns) >= 5
    assert "contextual_risk_score" in vulns[0]
    assert "epss_probability" in vulns[0]

    # Filter by priority
    resp_p0 = await async_client.get("/api/v1/asm/vulnerabilities?priority=P0_CRITICAL")
    assert resp_p0.status_code == 200
    for v in resp_p0.json():
        assert v["priority"] == "P0_CRITICAL"


@pytest.mark.asyncio
async def test_prioritize_and_remediate_vulnerability(async_client: AsyncClient):
    """Verifies recalculating prioritization and executing remediation."""
    # Prioritize
    resp_prio = await async_client.post(
        "/api/v1/asm/vulnerabilities/prioritize",
        json={"recalculate": True},
    )
    assert resp_prio.status_code == 200
    prio_list = resp_prio.json()
    assert len(prio_list) >= 5

    # Remediate CVE-2023-46805
    cve_id = "CVE-2023-46805"
    resp_rem = await async_client.post(
        f"/api/v1/asm/vulnerabilities/{cve_id}/remediate",
        json={
            "resolution_notes": "SOAR playbook PB-402 virtual patch applied to API Gateway",
            "action": "APPLY_VIRTUAL_PATCH",
        },
    )
    assert resp_rem.status_code == 200
    rem_data = resp_rem.json()
    assert rem_data["status"] == "REMEDIATED"
    assert "PB-402" in rem_data["resolution_notes"]

    # Remediate invalid CVE returns 404
    resp_404 = await async_client.post(
        "/api/v1/asm/vulnerabilities/CVE-UNKNOWN-99999/remediate",
        json={
            "resolution_notes": "Test invalid",
            "action": "APPLY_VIRTUAL_PATCH",
        },
    )
    assert resp_404.status_code == 404

