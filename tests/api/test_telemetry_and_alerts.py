"""API integration tests for telemetry ingestion, alerts, incidents, and audit logs."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoints(async_client: AsyncClient):
    """Verifies liveness and readiness probe responses."""
    live_resp = await async_client.get("/api/v1/health")
    assert live_resp.status_code == 200
    assert live_resp.json()["status"] == "healthy"

    ready_resp = await async_client.get("/api/v1/health/ready")
    assert ready_resp.status_code == 200
    assert "ready" in ready_resp.json()


@pytest.mark.asyncio
async def test_telemetry_ingest_and_list(async_client: AsyncClient):
    """Verifies ingesting normalized telemetry and querying it back."""
    payload = {
        "source_ip": "10.0.1.25",
        "destination_ip": "192.168.10.100",
        "source_port": 49152,
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "AUTH",
        "severity": "HIGH",
        "features": {"failed_attempts": 12, "flow_duration_s": 1.5},
        "metadata": {"auth_mechanism": "ssh_password"},
    }
    ingest_resp = await async_client.post("/api/v1/telemetry/ingest", json=payload)
    assert ingest_resp.status_code == 202
    data = ingest_resp.json()
    assert data["status"] == "ACCEPTED"
    assert "event_id" in data

    # Query events
    list_resp = await async_client.get("/api/v1/telemetry/events?source_ip=10.0.1.25")
    assert list_resp.status_code == 200
    events = list_resp.json()
    assert len(events) >= 1
    assert events[0]["source_ip"] == "10.0.1.25"
    assert events[0]["features"]["failed_attempts"] == 12


@pytest.mark.asyncio
async def test_alerts_lifecycle(async_client: AsyncClient, analyst_token: str):
    """Tests creating an alert, listing alerts, and updating alert status."""
    alert_payload = {
        "title": "Suspected SSH Brute Force Activity",
        "description": "Rapid succession of authentication failures detected from internal host",
        "detection_source": "XGBOOST",
        "confidence": 0.94,
        "anomaly_score": 0.88,
        "severity": "HIGH",
        "mitre_technique_id": "T1110.001",
        "mitre_tactic": "CREDENTIAL_ACCESS",
        "contributing_features": {"failed_attempts_rate": 8.5, "unique_users_tried": 4},
    }
    create_resp = await async_client.post("/api/v1/alerts", json=alert_payload)
    assert create_resp.status_code == 201
    alert_data = create_resp.json()
    alert_id = alert_data["id"]
    assert alert_data["status"] == "NEW"

    # List alerts
    list_resp = await async_client.get("/api/v1/alerts?severity=HIGH")
    assert list_resp.status_code == 200
    assert any(a["id"] == alert_id for a in list_resp.json())

    # Update status to TRIAGED (authenticated analyst)
    headers = {"Authorization": f"Bearer {analyst_token}"}
    patch_resp = await async_client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "TRIAGED"},
        headers=headers,
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "TRIAGED"


@pytest.mark.asyncio
async def test_incidents_and_attack_timeline(async_client: AsyncClient):
    """Tests incident creation and attack timeline event reconstruction."""
    inc_payload = {
        "title": "Lateral Movement and Credential Access Campaign",
        "description": "Correlated anomalous authentication followed by SMB port sweeps",
        "severity": "CRITICAL",
        "composite_risk_score": 85.0,
        "attack_stage": "LATERAL_MOVEMENT",
    }
    inc_resp = await async_client.post("/api/v1/incidents", json=inc_payload)
    assert inc_resp.status_code == 201
    incident = inc_resp.json()
    incident_id = incident["id"]

    # Append timeline entry
    timeline_payload = {
        "timestamp": "2026-09-12T10:00:00Z",
        "event_summary": "Multiple failed Kerberos ticket requests",
        "entity": "10.0.1.25",
        "detection_source": "UEBA",
        "mitre_technique": "T1558.003",
        "severity": "HIGH",
    }
    tl_resp = await async_client.post(
        f"/api/v1/incidents/{incident_id}/timeline",
        json=timeline_payload,
    )
    assert tl_resp.status_code == 201

    # Fetch incident with timeline
    get_resp = await async_client.get(f"/api/v1/incidents/{incident_id}")
    assert get_resp.status_code == 200
    fetched = get_resp.json()
    assert len(fetched["timeline_entries"]) == 1
    assert fetched["timeline_entries"][0]["mitre_technique"] == "T1558.003"


@pytest.mark.asyncio
async def test_audit_logs_role_protection(
    async_client: AsyncClient,
    admin_token: str,
    analyst_token: str,
):
    """Verifies that audit logs can be queried by ADMIN but are forbidden to ANALYST."""
    # Analyst attempt -> 403 Forbidden
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    analyst_resp = await async_client.get("/api/v1/audit/logs", headers=analyst_headers)
    assert analyst_resp.status_code == 403

    # Admin attempt -> 200 OK
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    admin_resp = await async_client.get("/api/v1/audit/logs", headers=admin_headers)
    assert admin_resp.status_code == 200
    logs = admin_resp.json()
    assert isinstance(logs, list)

