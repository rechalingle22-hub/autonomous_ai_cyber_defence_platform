# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API Integration tests for Threat Intelligence Endpoints."""

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
async def test_indicator_lookup_endpoint(async_client: AsyncClient):
    """Verifies bulk indicator reputation lookup endpoint."""
    payload = {
        "indicators": [
            "198.51.100.2",          # Seed malicious C2 IP
            "cdn-update-auth.com",    # Seed malicious phishing domain
            "8.8.8.8",               # Public benign DNS
        ]
    }
    resp = await async_client.post("/api/v1/threat-intel/lookup", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_queried"] == 3
    assert data["malicious_found"] >= 2
    results = data["results"]

    # 198.51.100.2 evaluation
    c2_res = results.get("198.51.100.2")
    assert c2_res is not None
    assert c2_res["is_malicious"] is True
    assert c2_res["reputation_score"] >= 90
    assert c2_res["threat_actor"] == "APT29"

    # Benign evaluation
    benign_res = results.get("8.8.8.8")
    assert benign_res is not None
    assert benign_res["is_malicious"] is False
    assert benign_res["reputation_score"] == 0


@pytest.mark.asyncio
async def test_create_and_list_indicators(async_client: AsyncClient):
    """Verifies analyst manual IOC submission and filtered listing."""
    unique_ip = f"192.0.2.{uuid.uuid4().hex[:3]}"
    new_ioc = {
        "indicator_type": "IP",
        "indicator_value": unique_ip,
        "reputation_score": 88,
        "threat_actor": "APT28",
        "malware_family": "X-Agent",
        "description": "Secondary C2 staging node",
        "tags": ["C2", "APT28"],
    }

    # 1. Create IOC
    create_resp = await async_client.post("/api/v1/threat-intel/indicators", json=new_ioc)
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["indicator_value"] == unique_ip
    assert created_data["threat_actor"] == "APT28"
    assert created_data["reputation_score"] == 88

    # 2. Duplicate rejection
    dup_resp = await async_client.post("/api/v1/threat-intel/indicators", json=new_ioc)
    assert dup_resp.status_code == 400

    # 3. List indicators with min_score filter
    list_resp = await async_client.get("/api/v1/threat-intel/indicators?min_score=80")
    assert list_resp.status_code == 200
    indicators = list_resp.json()
    assert len(indicators) >= 1
    assert any(i["indicator_value"] == unique_ip for i in indicators)


@pytest.mark.asyncio
async def test_threat_intel_stats_endpoint(async_client: AsyncClient):
    """Verifies operational threat intelligence metrics endpoint."""
    resp = await async_client.get("/api/v1/threat-intel/stats")
    assert resp.status_code == 200
    stats = resp.json()

    assert stats["total_indicators_cached"] > 0
    assert stats["threat_actors_tracked"] >= 5
    assert stats["cves_mapped"] >= 5
    assert "SEED_INTEL_FEED" in stats["active_feeds"]


@pytest.mark.asyncio
async def test_threat_actors_endpoint(async_client: AsyncClient):
    """Verifies catalog of adversary group profiles."""
    resp = await async_client.get("/api/v1/threat-intel/actors")
    assert resp.status_code == 200
    actors = resp.json()
    assert len(actors) >= 5

    names = [a["actor_name"] for a in actors]
    assert "APT28" in names
    assert "APT29" in names
    assert "Lazarus Group" in names


@pytest.mark.asyncio
async def test_cve_mapping_endpoint(async_client: AsyncClient):
    """Verifies mapped CVE lookup by destination port."""
    # Lookup all CVEs
    all_resp = await async_client.get("/api/v1/threat-intel/cves")
    assert all_resp.status_code == 200
    all_cves = all_resp.json()
    assert len(all_cves) >= 5

    # Filter by SMB port 445
    smb_resp = await async_client.get("/api/v1/threat-intel/cves?port=445")
    assert smb_resp.status_code == 200
    smb_cves = smb_resp.json()
    cve_ids = [c["cve_id"] for c in smb_cves]
    assert "CVE-2017-0144" in cve_ids

