# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API integration tests for Security Chaos Engineering & Adversarial Resilience endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.chaos.engine import chaos_engine


@pytest.fixture(autouse=True)
def reset_chaos_leases():
    """Ensure chaos engine has zero active leases before and after tests."""
    chaos_engine.recover_all()
    yield
    chaos_engine.recover_all()


@pytest.mark.asyncio
async def test_get_chaos_status(async_client: AsyncClient):
    """Verifies retrieving platform resilience score and chaos status."""
    resp = await async_client.get("/api/v1/chaos/status")
    assert resp.status_code == 200
    data = resp.json()

    assert "resilience_score" in data
    assert "system_state" in data
    assert data["system_state"] == "STEADY_STATE"
    assert data["resilience_score"] == 100.0
    assert data["zero_downtime_guaranteed"] is True
    assert data["in_memory_fallbacks_operational"] is True


@pytest.mark.asyncio
async def test_inject_and_recover_chaos_lifecycle(async_client: AsyncClient):
    """Verifies full lifecycle of injecting a fault, verifying degraded resilience, and recovering."""
    # 1. Inject fault
    inject_resp = await async_client.post(
        "/api/v1/chaos/inject",
        json={
            "experiment_type": "BROKER_LATENCY",
            "duration_seconds": 30,
            "params": {"latency_ms": 250},
        },
    )
    assert inject_resp.status_code == 201
    inj_data = inject_resp.json()
    exp_id = inj_data["id"]
    assert inj_data["status"] == "ACTIVE"
    assert inj_data["experiment_type"] == "BROKER_LATENCY"

    # 2. Check status shows active fault and reduced score
    status_resp = await async_client.get("/api/v1/chaos/status")
    assert status_resp.status_code == 200
    st_data = status_resp.json()
    assert st_data["system_state"] == "CHAOS_INJECTED"
    assert st_data["active_faults_count"] == 1
    assert st_data["resilience_score"] < 100.0

    # 3. Check experiments listing
    list_resp = await async_client.get("/api/v1/chaos/experiments")
    assert list_resp.status_code == 200
    experiments = list_resp.json()
    assert any(e["id"] == exp_id for e in experiments)

    # 4. Recover specific experiment
    rec_resp = await async_client.post(
        "/api/v1/chaos/recover",
        json={"experiment_id": exp_id},
    )
    assert rec_resp.status_code == 200
    rec_data = rec_resp.json()
    assert len(rec_data) == 1
    assert rec_data[0]["status"] == "RECOVERED"

    # 5. Confirm system returns to steady state
    status_recovered = await async_client.get("/api/v1/chaos/status")
    assert status_recovered.json()["system_state"] == "STEADY_STATE"
    assert status_recovered.json()["resilience_score"] == 100.0


@pytest.mark.asyncio
async def test_inject_invalid_experiment_type(async_client: AsyncClient):
    """Verifies rejecting invalid experiment types."""
    resp = await async_client.post(
        "/api/v1/chaos/inject",
        json={
            "experiment_type": "INVALID_EXPLOSION",
            "duration_seconds": 30,
        },
    )
    assert resp.status_code == 400
    assert "Invalid experiment_type" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_evaluate_adversarial_robustness_endpoint(async_client: AsyncClient):
    """Verifies evaluating ensemble adversarial evasion robustness via REST API."""
    resp = await async_client.post(
        "/api/v1/chaos/adversarial/evaluate",
        json={
            "perturbation_epsilon": 0.15,
            "technique": "BENIGN_MIMICRY",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert "total_attack_samples_tested" in data
    assert "ensemble_adversarial_robustness_index" in data
    assert "ensemble_robustness_grade" in data
    assert data["ensemble_robustness_grade"] in ("A", "B", "C")
    assert "models" in data
    assert len(data["models"]) >= 2

