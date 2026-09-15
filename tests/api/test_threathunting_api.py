# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API integration tests for Threat Hunting & Autonomous Detection-as-Code endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.threathunting.engine import threathunting_engine


@pytest.mark.asyncio
async def test_get_hunting_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving Threat Hunting metrics."""
    resp = await async_client.get("/api/v1/threathunting/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "total_hypotheses" in data
    assert "total_detection_rules" in data
    assert "hypothesis_validation_rate" in data
    assert data["total_hypotheses"] >= 5
    assert data["deployed_active_rules"] >= 2


@pytest.mark.asyncio
async def test_list_hypotheses_endpoint(async_client: AsyncClient):
    """Verifies retrieving the hunting hypothesis catalog."""
    resp = await async_client.get("/api/v1/threathunting/hypotheses")
    assert resp.status_code == 200
    hyps = resp.json()

    assert len(hyps) >= 5
    first = hyps[0]
    assert "mitre_technique" in first
    assert "query_logic" in first
    assert "tactic" in first


@pytest.mark.asyncio
async def test_execute_hunt_endpoint(async_client: AsyncClient):
    """Verifies executing a threat hunt via API."""
    # 1. Valid execution
    resp = await async_client.post(
        "/api/v1/threathunting/hunts/execute",
        json={"hypothesis_id": "HYP-002", "time_window_hours": 24},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["hypothesis_id"] == "HYP-002"
    assert data["confidence_score"] >= 80.0
    assert len(data["matched_iocs"]) >= 1

    # 2. Unknown hypothesis returns 404
    resp_bad = await async_client.post(
        "/api/v1/threathunting/hunts/execute",
        json={"hypothesis_id": "HYP-NONEXISTENT", "time_window_hours": 12},
    )
    assert resp_bad.status_code == 404


@pytest.mark.asyncio
async def test_hunt_history_endpoint(async_client: AsyncClient):
    """Verifies retrieving past hunt executions history."""
    resp = await async_client.get("/api/v1/threathunting/hunts/history")
    assert resp.status_code == 200
    history = resp.json()
    assert isinstance(history, list)
    assert len(history) >= 1


@pytest.mark.asyncio
async def test_list_and_filter_rules_endpoint(async_client: AsyncClient):
    """Verifies listing detection rules and applying format filters."""
    # List all rules
    resp_all = await async_client.get("/api/v1/threathunting/rules")
    assert resp_all.status_code == 200
    rules = resp_all.json()
    assert len(rules) >= 2

    # Filter by SIGMA_YAML
    resp_sigma = await async_client.get("/api/v1/threathunting/rules?format=SIGMA_YAML")
    assert resp_sigma.status_code == 200
    for r in resp_sigma.json():
        assert r["format"] == "SIGMA_YAML"

    # Filter by YARA
    resp_yara = await async_client.get("/api/v1/threathunting/rules?format=YARA")
    assert resp_yara.status_code == 200
    for r in resp_yara.json():
        assert r["format"] == "YARA"


@pytest.mark.asyncio
async def test_generate_and_deploy_rule_endpoint(async_client: AsyncClient):
    """Verifies synthesizing a new rule and deploying it to active detection."""
    # 1. Generate Sigma Rule
    resp_gen = await async_client.post(
        "/api/v1/threathunting/rules/generate",
        json={
            "hypothesis_id": "HYP-003",
            "rule_format": "SIGMA_YAML",
            "title": "API Test Sigma Rule for LSASS Access",
            "severity": "critical",
        },
    )
    assert resp_gen.status_code == 201
    new_rule = resp_gen.json()
    assert new_rule["format"] == "SIGMA_YAML"
    assert new_rule["status"] == "VALIDATED"
    rule_id = new_rule["id"]

    # 2. Deploy Rule
    resp_deploy = await async_client.post(f"/api/v1/threathunting/rules/{rule_id}/deploy")
    assert resp_deploy.status_code == 200
    deployed = resp_deploy.json()
    assert deployed["status"] == "DEPLOYED_ACTIVE"
    assert deployed["deployed_at"] is not None

    # 3. Deploy invalid rule returns 404
    resp_deploy_404 = await async_client.post("/api/v1/threathunting/rules/invalid-rule-999/deploy")
    assert resp_deploy_404.status_code == 404

