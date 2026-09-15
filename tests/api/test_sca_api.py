# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""API integration tests for Software Supply Chain Security (SCA) & SBOM Governance endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.sca.engine import sca_engine


@pytest.mark.asyncio
async def test_get_sca_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving supply chain posture metrics."""
    resp = await async_client.get("/api/v1/sca/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "health_score" in data
    assert "total_sboms" in data
    assert "total_components" in data
    assert data["total_sboms"] >= 3
    assert data["total_components"] >= 18
    assert data["open_vulnerabilities"] >= 5


@pytest.mark.asyncio
async def test_list_sboms_endpoint(async_client: AsyncClient):
    """Verifies listing registered SBOMs."""
    resp = await async_client.get("/api/v1/sca/sboms")
    assert resp.status_code == 200
    sboms = resp.json()

    assert len(sboms) >= 3
    ids = [s["sbom_id"] for s in sboms]
    assert "SBOM-CORE-API" in ids
    assert "SBOM-WEB-UI" in ids
    assert "SBOM-INGRESS-GW" in ids


@pytest.mark.asyncio
async def test_export_cyclonedx_endpoint(async_client: AsyncClient):
    """Verifies CycloneDX v1.5 JSON export endpoint."""
    resp = await async_client.get("/api/v1/sca/sboms/SBOM-CORE-API/export")
    assert resp.status_code == 200
    cyclonedx = resp.json()

    assert cyclonedx["bomFormat"] == "CycloneDX"
    assert cyclonedx["specVersion"] == "1.5"
    assert len(cyclonedx["components"]) > 0

    # 404 on invalid SBOM ID
    resp_404 = await async_client.get("/api/v1/sca/sboms/INVALID-SBOM/export")
    assert resp_404.status_code == 404


@pytest.mark.asyncio
async def test_list_components_and_filter_endpoint(async_client: AsyncClient):
    """Verifies component listing with ecosystem filtering."""
    resp = await async_client.get("/api/v1/sca/components")
    assert resp.status_code == 200
    all_comps = resp.json()
    assert len(all_comps) >= 18

    resp_pypi = await async_client.get("/api/v1/sca/components?ecosystem=pypi")
    assert resp_pypi.status_code == 200
    pypi_comps = resp_pypi.json()
    assert len(pypi_comps) >= 8
    for c in pypi_comps:
        assert c["ecosystem"] == "pypi"


@pytest.mark.asyncio
async def test_list_vulnerabilities_and_filter_endpoint(async_client: AsyncClient):
    """Verifies vulnerability listing with severity and CISA KEV filtering."""
    resp = await async_client.get("/api/v1/sca/vulnerabilities")
    assert resp.status_code == 200
    all_vulns = resp.json()
    assert len(all_vulns) >= 6

    # Filter CISA KEV
    resp_kev = await async_client.get("/api/v1/sca/vulnerabilities?cisa_kev_only=true")
    assert resp_kev.status_code == 200
    kev_vulns = resp_kev.json()
    assert len(kev_vulns) >= 2
    for v in kev_vulns:
        assert v["cisa_kev"] is True


@pytest.mark.asyncio
async def test_threats_and_licenses_endpoints(async_client: AsyncClient):
    """Verifies threats and license risks endpoints."""
    resp_threats = await async_client.get("/api/v1/sca/threats")
    assert resp_threats.status_code == 200
    threats = resp_threats.json()
    assert len(threats) >= 3

    resp_licenses = await async_client.get("/api/v1/sca/licenses")
    assert resp_licenses.status_code == 200
    licenses = resp_licenses.json()
    assert len(licenses) >= 1
    assert licenses[0]["license"] == "AGPL-3.0"


@pytest.mark.asyncio
async def test_patch_and_remediation_endpoints(async_client: AsyncClient):
    """Verifies patch retrieval, autonomous remediation execution, and error handling."""
    # 1. Fetch patch
    resp_patch = await async_client.get("/api/v1/sca/vulnerabilities/VULN-002/patch")
    assert resp_patch.status_code == 200
    patch = resp_patch.json()
    assert patch["cve_id"] == "CVE-2023-45857"
    assert "unified_diff" in patch

    # 2. Remediate
    resp_rem = await async_client.post(
        "/api/v1/sca/remediate",
        json={"vuln_id": "VULN-002"},
    )
    assert resp_rem.status_code == 200
    rem = resp_rem.json()
    assert rem["status"] == "SUCCESS"
    assert rem["vulnerability_status"] == "REMEDIATED"
    assert "audit_trail_id" in rem

    # 3. Non-existent IDs
    resp_404_patch = await async_client.get("/api/v1/sca/vulnerabilities/INVALID/patch")
    assert resp_404_patch.status_code == 404

    resp_404_rem = await async_client.post(
        "/api/v1/sca/remediate",
        json={"vuln_id": "INVALID"},
    )
    assert resp_404_rem.status_code == 404

