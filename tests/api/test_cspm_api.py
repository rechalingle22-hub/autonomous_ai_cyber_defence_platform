# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""API integration tests for Cloud Security Posture Management (CSPM) & IaC Guard endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.cspm.engine import cspm_engine


@pytest.mark.asyncio
async def test_get_cspm_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving global multi-cloud CSPM and CIS metrics."""
    resp = await async_client.get("/api/v1/cspm/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "overall_cis_compliance_percent" in data
    assert "total_cloud_resources_scanned" in data
    assert "compliance_by_provider" in data
    assert data["total_findings_count"] >= 6


@pytest.mark.asyncio
async def test_list_policies_endpoint(async_client: AsyncClient):
    """Verifies retrieving registered CIS benchmark policies."""
    resp = await async_client.get("/api/v1/cspm/policies")
    assert resp.status_code == 200
    policies = resp.json()

    assert len(policies) >= 6
    p_ids = [p["policy_id"] for p in policies]
    assert "CIS-AWS-2.1.5" in p_ids
    assert "CIS-K8S-5.2.1" in p_ids


@pytest.mark.asyncio
async def test_list_findings_and_filters_endpoint(async_client: AsyncClient):
    """Verifies listing findings and testing query parameter filters."""
    # 1. Unfiltered
    resp = await async_client.get("/api/v1/cspm/findings")
    assert resp.status_code == 200
    all_findings = resp.json()
    assert len(all_findings) >= 6

    # 2. Filter by provider=AWS
    resp_aws = await async_client.get("/api/v1/cspm/findings?provider=AWS")
    assert resp_aws.status_code == 200
    aws_findings = resp_aws.json()
    assert len(aws_findings) >= 2
    assert all(f["provider"] == "AWS" for f in aws_findings)

    # 3. Filter by severity=CRITICAL
    resp_crit = await async_client.get("/api/v1/cspm/findings?severity=CRITICAL")
    assert resp_crit.status_code == 200
    crit_findings = resp_crit.json()
    assert len(crit_findings) >= 2
    assert all(f["severity"] == "CRITICAL" for f in crit_findings)


@pytest.mark.asyncio
async def test_get_single_finding_and_patch_endpoint(async_client: AsyncClient):
    """Verifies fetching finding details and its synthesized IaC patch."""
    resp_find = await async_client.get("/api/v1/cspm/findings/FIND-AWS-001")
    assert resp_find.status_code == 200
    find_data = resp_find.json()
    assert find_data["finding_id"] == "FIND-AWS-001"
    assert "s3_storage" in find_data["iac_file_path"]

    # Fetch patch
    resp_patch = await async_client.get("/api/v1/cspm/findings/FIND-AWS-001/patch")
    assert resp_patch.status_code == 200
    patch_data = resp_patch.json()
    assert patch_data["finding_id"] == "FIND-AWS-001"
    assert "aws_s3_bucket_public_access_block" in patch_data["unified_diff"]

    # Unknown finding patch returns 404
    resp_bad = await async_client.get("/api/v1/cspm/findings/FIND-UNKNOWN/patch")
    assert resp_bad.status_code == 404


@pytest.mark.asyncio
async def test_remediate_finding_endpoint(async_client: AsyncClient):
    """Verifies autonomous IaC remediation and Git PR payload synthesis."""
    resp = await async_client.post("/api/v1/cspm/findings/FIND-AWS-001/remediate")
    assert resp.status_code == 200
    data = resp.json()

    assert data["finding_id"] == "FIND-AWS-001"
    assert data["status"] == "REMEDIATED"
    assert data["pull_request_id"].startswith("PR-CSPM-")
    assert data["new_compliance_score"] > 85.0

    # Remediate non-existent finding returns 404
    resp_bad = await async_client.post("/api/v1/cspm/findings/FIND-UNKNOWN/remediate")
    assert resp_bad.status_code == 404

    # Reset findings
    resp_reset = await async_client.post("/api/v1/cspm/reset")
    assert resp_reset.status_code == 200
    assert resp_reset.json()["status"] == "RESET_SUCCESS"

