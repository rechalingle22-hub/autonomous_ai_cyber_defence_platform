# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Model Registry, Version Lifecycle Manager, and Retraining Pipeline."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from tests.conftest import TestingSessionLocal
from ml.registry.version_manager import model_registry
from ml.training.retrain_pipeline import retraining_pipeline
from backend.app.models.model_registry import ModelFamily


@pytest.mark.asyncio
async def test_seed_initial_registry():
    """Verifies that seeding produces the standard default production models."""
    async with TestingSessionLocal() as db:
        await model_registry.seed_initial_registry(db)
        models = await model_registry.list_models(db)
        assert len(models) >= 4

        names = [m.model_name for m in models]
        assert "xgboost_attack_classifier" in names
        assert "random_forest_classifier" in names
        assert "isolation_forest_detector" in names
        assert "autoencoder_detector" in names


@pytest.mark.asyncio
async def test_register_and_promote_version():
    """Verifies registering challenger versions and atomically promoting them to champion."""
    async with TestingSessionLocal() as db:
        # Register v1 as deployed
        v1 = await model_registry.register_version(
            db=db,
            model_name="test_xgboost",
            family=ModelFamily.XGBOOST,
            version="v1.0.0",
            metrics={"f1": 0.90, "precision": 0.89, "recall": 0.91},
            artifact_path="ml/artifacts/test_v1.joblib",
            is_deployed=True,
        )
        assert v1.is_deployed is True

        # Register v2 as challenger (not deployed)
        v2 = await model_registry.register_version(
            db=db,
            model_name="test_xgboost",
            family=ModelFamily.XGBOOST,
            version="v2.0.0",
            metrics={"f1": 0.96, "precision": 0.95, "recall": 0.97},
            artifact_path="ml/artifacts/test_v2.joblib",
            is_deployed=False,
        )
        assert v2.is_deployed is False

        # Promote v2 to champion
        promoted_v2 = await model_registry.promote_version(db, v2.id)
        assert promoted_v2.is_deployed is True
        assert promoted_v2.version == "v2.0.0"

        # Check that v1 was demoted
        versions = await model_registry.get_model_versions(db, v1.model_id)
        v1_reloaded = next(v for v in versions if v.id == v1.id)
        assert v1_reloaded.is_deployed is False


@pytest.mark.asyncio
async def test_record_drift_metric():
    """Verifies persisting drift metrics associated with a model version."""
    async with TestingSessionLocal() as db:
        v = await model_registry.register_version(
            db=db,
            model_name="drift_monitored_model",
            family=ModelFamily.ISOLATION_FOREST,
            version="v1.0.0",
            metrics={"f1": 0.95},
            artifact_path="ml/artifacts/iso.joblib",
            is_deployed=True,
        )

        metric = await model_registry.record_drift_metric(
            db=db,
            model_version_id=v.id,
            psi_metric=0.18,
            ks_pvalue=0.002,
            drift_detected=True,
            drifted_features={"drifted": ["port_entropy", "failed_logins_window"]},
        )

        assert metric.id is not None
        assert metric.psi_metric == 0.18
        assert metric.drift_detected is True
        assert "port_entropy" in metric.drifted_features["drifted"]


@pytest.mark.asyncio
async def test_retraining_pipeline_execution():
    """Verifies running the retraining pipeline to produce challenger models."""
    async with TestingSessionLocal() as db:
        res = await retraining_pipeline.run_retraining_job(
            db=db,
            trigger_reason="TEST_SUITE_TRIGGER",
            auto_promote=True,
        )

        assert res["status"] == "COMPLETED"
        assert res["training_samples"] > 0
        assert "xgboost" in res["models_evaluated"]
        assert "random_forest" in res["models_evaluated"]
        assert res["models_evaluated"]["xgboost"]["metrics"]["f1"] >= 0.80
        assert res["models_evaluated"]["random_forest"]["metrics"]["f1"] >= 0.80

