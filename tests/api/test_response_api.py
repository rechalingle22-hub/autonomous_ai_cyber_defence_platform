# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API Integration tests for SOAR and Automated Incident Response Endpoints."""

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
async def test_list_actions_endpoint(async_client: AsyncClient):
    """Verifies retrieval of response actions list."""
    resp = await async_client.get("/api/v1/response/actions")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_create_and_execute_action_endpoint(async_client: AsyncClient):
    """Verifies creating and auto-executing an action with low risk score."""
    payload = {
        "incident_id": "STANDALONE",
        "action_type": "BLOCK_IP",
        "target_entity": "198.51.100.99",
        "risk_impact_score": 30.0,
        "is_simulation": True,
        "rationale": "Active port scanner",
    }
    resp = await async_client.post("/api/v1/response/actions", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["target_entity"] == "198.51.100.99"
    assert data["action_type"] == "BLOCK_IP"
    assert data["status"] == "EXECUTED"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_action_pending_approval_and_approve(async_client: AsyncClient):
    """Verifies high-risk action requires human approval and can be approved."""
    # 1. Create high-risk action
    payload = {
        "incident_id": "STANDALONE",
        "action_type": "ISOLATE_HOST",
        "target_entity": "srv-finance-main",
        "risk_impact_score": 80.0,
        "is_simulation": True,
        "rationale": "Ransomware encryption trigger",
    }
    resp = await async_client.post("/api/v1/response/actions", json=payload)
    assert resp.status_code == 201
    action = resp.json()
    assert action["status"] == "PENDING_APPROVAL"
    action_id = action["id"]

    # 2. Approve action
    appr_payload = {"comments": "Approved by senior SOC analyst"}
    appr_resp = await async_client.post(f"/api/v1/response/actions/{action_id}/approve", json=appr_payload)
    assert appr_resp.status_code == 200
    appr_data = appr_resp.json()
    assert appr_data["success"] is True
    assert appr_data["status"] == "EXECUTED"


@pytest.mark.asyncio
async def test_create_action_pending_approval_and_reject(async_client: AsyncClient):
    """Verifies high-risk action can be rejected by analyst."""
    payload = {
        "incident_id": "STANDALONE",
        "action_type": "ISOLATE_HOST",
        "target_entity": "srv-executive-gateway",
        "risk_impact_score": 90.0,
        "is_simulation": True,
        "rationale": "Potential false positive isolation proposal",
    }
    resp = await async_client.post("/api/v1/response/actions", json=payload)
    assert resp.status_code == 201
    action_id = resp.json()["id"]

    # Reject action
    rej_payload = {"comments": "Rejected: Verified benign traffic anomaly"}
    rej_resp = await async_client.post(f"/api/v1/response/actions/{action_id}/reject", json=rej_payload)
    assert rej_resp.status_code == 200
    rej_data = rej_resp.json()
    assert rej_data["status"] == "REJECTED"


@pytest.mark.asyncio
async def test_action_rollback_endpoint(async_client: AsyncClient):
    """Verifies rollback undo for an executed action."""
    # 1. Create executed action
    payload = {
        "incident_id": "STANDALONE",
        "action_type": "BLOCK_IP",
        "target_entity": "198.51.100.105",
        "risk_impact_score": 20.0,
        "is_simulation": True,
        "rationale": "Temporary block for verification",
    }
    create_resp = await async_client.post("/api/v1/response/actions", json=payload)
    assert create_resp.status_code == 201
    action_id = create_resp.json()["id"]

    # 2. Rollback action
    rb_resp = await async_client.post(f"/api/v1/response/actions/{action_id}/rollback")
    assert rb_resp.status_code == 200
    rb_data = rb_resp.json()
    assert rb_data["success"] is True


@pytest.mark.asyncio
async def test_list_playbooks_endpoint(async_client: AsyncClient):
    """Verifies listing of all declarative SOAR playbooks."""
    resp = await async_client.get("/api/v1/response/playbooks")
    assert resp.status_code == 200
    playbooks = resp.json()
    assert isinstance(playbooks, list)
    assert len(playbooks) >= 4

    p_ids = [p["playbook_id"] for p in playbooks]
    assert "PB-RANSOMWARE-01" in p_ids
    assert "PB-EXFILTRATION-01" in p_ids
    assert "PB-RECON-01" in p_ids


@pytest.mark.asyncio
async def test_execute_playbook_endpoint(async_client: AsyncClient):
    """Verifies triggering on-demand playbook execution."""
    payload = {
        "playbook_id": "PB-RECON-01",
        "incident_id": "INC-TEST-SIM-01",
        "is_simulation": True,
    }
    resp = await async_client.post("/api/v1/response/playbooks/execute", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["playbook_id"] == "PB-RECON-01"
    assert data["success"] is True
    assert data["steps_executed"] >= 1


@pytest.mark.asyncio
async def test_soar_stats_endpoint(async_client: AsyncClient):
    """Verifies aggregated SOAR metrics and posture endpoint."""
    resp = await async_client.get("/api/v1/response/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert "total_actions" in stats
    assert "active_playbooks_count" in stats
    assert stats["active_playbooks_count"] >= 4
    assert stats["simulation_mode_enabled"] is True

