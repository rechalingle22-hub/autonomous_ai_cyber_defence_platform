# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API tests for Incidents, Attack Timeline, and Correlation Trigger Endpoints."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import pytest  # type: ignore
from httpx import AsyncClient  # type: ignore



@pytest.mark.asyncio
async def test_incidents_filtering_and_patch(async_client: AsyncClient):
    """Verifies creating, filtering, and updating incident state."""
    # Create high severity incident
    inc_payload = {
        "title": "Suspected Ransomware Propagation",
        "description": "Rapid mass file encryption and SMB share traversal observed",
        "severity": "CRITICAL",
        "composite_risk_score": 92.5,
        "attack_stage": "IMPACT",
    }
    create_resp = await async_client.post("/api/v1/incidents", json=inc_payload)
    assert create_resp.status_code == 201
    inc_data = create_resp.json()
    inc_id = inc_data["id"]
    assert inc_data["status"] == "OPEN"
    assert inc_data["severity"] == "CRITICAL"

    # Filter by severity
    filter_resp = await async_client.get("/api/v1/incidents?severity=CRITICAL")
    assert filter_resp.status_code == 200
    incidents = filter_resp.json()
    assert any(i["id"] == inc_id for i in incidents)

    # Patch incident status to INVESTIGATING
    patch_resp = await async_client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"status": "INVESTIGATING", "composite_risk_score": 95.0},
    )
    assert patch_resp.status_code == 200
    updated = patch_resp.json()
    assert updated["status"] == "INVESTIGATING"
    assert updated["composite_risk_score"] == 95.0


@pytest.mark.asyncio
async def test_incident_timeline_endpoint(async_client: AsyncClient):
    """Verifies chronological attack timeline endpoint for an incident."""
    inc_payload = {
        "title": "Data Exfiltration Over DNS Tunnel",
        "description": "High volume of encoded subdomains querying suspicious nameservers",
        "severity": "HIGH",
        "composite_risk_score": 78.0,
        "attack_stage": "EXFILTRATION",
    }
    create_resp = await async_client.post("/api/v1/incidents", json=inc_payload)
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    # Append timeline step 1
    t1_payload = {
        "timestamp": "2026-09-13T01:00:00Z",
        "event_summary": "Unusual TXT record query volume",
        "entity": "10.0.2.15 -> 8.8.8.8",
        "detection_source": "AUTOENCODER",
        "mitre_technique": "T1071.004",
        "severity": "MEDIUM",
    }
    await async_client.post(f"/api/v1/incidents/{inc_id}/timeline", json=t1_payload)

    # Append timeline step 2
    t2_payload = {
        "timestamp": "2026-09-13T01:05:00Z",
        "event_summary": "Base64 encoded payload in DNS query",
        "entity": "10.0.2.15 -> 198.51.100.22",
        "detection_source": "XGBOOST",
        "mitre_technique": "T1048",
        "severity": "HIGH",
    }
    await async_client.post(f"/api/v1/incidents/{inc_id}/timeline", json=t2_payload)

    # Fetch dedicated timeline endpoint
    tl_resp = await async_client.get(f"/api/v1/incidents/{inc_id}/timeline")
    assert tl_resp.status_code == 200
    steps = tl_resp.json()
    assert len(steps) == 2
    assert steps[0]["mitre_technique"] == "T1071.004"
    assert steps[1]["mitre_technique"] == "T1048"

    # Test non-existent incident
    not_found_resp = await async_client.get("/api/v1/incidents/00000000-0000-0000-0000-000000000000/timeline")
    assert not_found_resp.status_code == 404


@pytest.mark.asyncio
async def test_trigger_alert_correlation_endpoint(async_client: AsyncClient):
    """Verifies the /incidents/correlate endpoint batches and correlates pending alerts."""
    # Seed alerts without incident_id
    alert1 = {
        "title": "Port Sweep on Database Subnet",
        "description": "SYN scanning detected across 10.0.5.0/24",
        "detection_source": "ISOLATION_FOREST",
        "confidence": 0.82,
        "anomaly_score": 0.79,
        "severity": "MEDIUM",
        "mitre_technique_id": "T1046",
        "mitre_tactic": "PORT_SCAN",
        "contributing_features": {"source_ip": "172.20.1.50", "destination_ip": "10.0.5.10"},
    }
    alert2 = {
        "title": "SQL Injection Attempt",
        "description": "UNION SELECT payload detected in HTTP query",
        "detection_source": "XGBOOST",
        "confidence": 0.94,
        "anomaly_score": 0.88,
        "severity": "HIGH",
        "mitre_technique_id": "T1190",
        "mitre_tactic": "WEB_ATTACK",
        "contributing_features": {"source_ip": "172.20.1.50", "destination_ip": "10.0.5.10"},
    }

    a1_resp = await async_client.post("/api/v1/alerts", json=alert1)
    assert a1_resp.status_code == 201
    a2_resp = await async_client.post("/api/v1/alerts", json=alert2)
    assert a2_resp.status_code == 201

    # Trigger correlation
    corr_resp = await async_client.post("/api/v1/incidents/correlate?limit=50")
    assert corr_resp.status_code == 200
    corr_data = corr_resp.json()
    assert corr_data["status"] == "success"
    assert corr_data["processed_alerts"] >= 2
    assert len(corr_data["results"]) >= 2

