# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API integration tests for Continuous MLOps & Model Governance endpoints."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


@pytest.mark.asyncio
async def test_get_drift_metrics_endpoint(async_client: AsyncClient):
    """Verifies retrieving baseline-vs-operational drift metrics."""
    resp = await async_client.get("/api/v1/mlops/drift")
    assert resp.status_code == 200
    data = resp.json()

    assert "drift_detected" in data
    assert "status" in data
    assert "mean_psi" in data
    assert "max_psi" in data
    assert "feature_metrics" in data
    assert data["total_features_evaluated"] == 14


@pytest.mark.asyncio
async def test_evaluate_drift_on_demand_endpoint(async_client: AsyncClient):
    """Verifies triggering on-demand drift evaluation with both normal and simulated drift."""
    # 1. Normal traffic window
    resp_norm = await async_client.post(
        "/api/v1/mlops/drift/evaluate",
        json={"sample_count": 200, "introduce_drift": False},
    )
    assert resp_norm.status_code == 200
    data_norm = resp_norm.json()
    assert data_norm["status"] in ("STABLE", "WARNING")

    # 2. Simulated covariate drift window
    resp_drift = await async_client.post(
        "/api/v1/mlops/drift/evaluate",
        json={"sample_count": 200, "introduce_drift": True},
    )
    assert resp_drift.status_code == 200
    data_drift = resp_drift.json()
    assert data_drift["drift_detected"] is True
    assert data_drift["status"] in ("WARNING", "CRITICAL")
    assert data_drift["max_psi"] >= 0.25


@pytest.mark.asyncio
async def test_list_models_and_versions_endpoint(async_client: AsyncClient):
    """Verifies listing registered production models and inspecting version history."""
    resp = await async_client.get("/api/v1/mlops/models")
    assert resp.status_code == 200
    models = resp.json()
    assert len(models) >= 4

    target_model = models[0]
    assert "id" in target_model
    assert "model_name" in target_model
    assert "versions" in target_model

    # Get version history
    v_resp = await async_client.get(f"/api/v1/mlops/models/{target_model['id']}/versions")
    assert v_resp.status_code == 200
    versions = v_resp.json()
    assert len(versions) >= 1
    assert "validation_f1" in versions[0]


@pytest.mark.asyncio
async def test_promote_model_version_endpoint(async_client: AsyncClient):
    """Verifies promoting a challenger version to active champion."""
    # Fetch models
    m_resp = await async_client.get("/api/v1/mlops/models")
    models = m_resp.json()
    version_id = models[0]["versions"][0]["id"]

    # Promote
    resp = await async_client.post(f"/api/v1/mlops/models/{version_id}/promote")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_deployed"] is True


@pytest.mark.asyncio
async def test_trigger_retraining_endpoint(async_client: AsyncClient):
    """Verifies executing automated model retraining via REST API."""
    payload = {
        "trigger_reason": "API_INTEGRATION_TEST",
        "auto_promote": True,
    }
    resp = await async_client.post("/api/v1/mlops/retrain", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert data["status"] == "COMPLETED"
    assert "job_id" in data
    assert "version" in data
    assert data["training_samples"] > 0
    assert "xgboost" in data["models_evaluated"]
    assert "random_forest" in data["models_evaluated"]

