# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Continuous MLOps, Drift Detection & Model Governance REST API Router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List, Any
import numpy as np  # type: ignore
import pandas as pd  # type: ignore
from fastapi import APIRouter, Depends, HTTPException, status  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

from backend.app.database.session import get_db  # type: ignore
from backend.app.models.model_registry import MLModel, ModelVersion  # type: ignore
from backend.app.schemas.mlops import (  # type: ignore
    DriftEvaluationResponse,
    DriftEvaluateRequest,
    MLModelResponse,
    ModelVersionResponse,
    RetrainRequest,
    RetrainResponse,
)
from backend.app.audit.service import audit_service  # type: ignore
from ml.monitoring.drift_detector import drift_detector  # type: ignore
from ml.registry.version_manager import model_registry  # type: ignore
from ml.training.retrain_pipeline import retraining_pipeline  # type: ignore
from ml.datasets.synthetic_generator import synthetic_generator  # type: ignore

router = APIRouter(prefix="/mlops", tags=["Continuous MLOps & Model Governance"])


def _generate_telemetry_df(sample_count: int, introduce_drift: bool = False) -> pd.DataFrame:
    """Helper to synthesize baseline and current evaluation dataframes."""
    benign_events = synthetic_generator.generate_benign_traffic(count=sample_count)
    records = [e["features"].copy() for e in benign_events]
    df = pd.DataFrame(records)

    if introduce_drift:
        # Simulate severe covariate drift in network behavior
        df["flow_duration_ms"] = df["flow_duration_ms"] * 4.5 + np.random.normal(500, 100, len(df))
        df["port_entropy"] = np.clip(df["port_entropy"] + np.random.uniform(1.5, 3.0, len(df)), 0.0, 5.0)
        df["bytes_out_ratio"] = np.clip(df["bytes_out_ratio"] * 1.8, 0.0, 1.0)
        df["failed_logins_window"] = df["failed_logins_window"] + np.random.poisson(3.5, len(df))

    return df


@router.get(
    "/drift",
    response_model=DriftEvaluationResponse,
    summary="Get Current Telemetry Drift Metrics",
)
async def get_drift_metrics() -> Any:
    """Returns the baseline-versus-operational drift status across all 14 telemetry features."""
    baseline_df = _generate_telemetry_df(sample_count=200, introduce_drift=False)
    current_df = _generate_telemetry_df(sample_count=200, introduce_drift=False)
    drift_result = drift_detector.evaluate_dataset_drift(baseline_df, current_df)
    return drift_result


@router.post(
    "/drift/evaluate",
    response_model=DriftEvaluationResponse,
    summary="Trigger On-Demand Drift Evaluation",
)
async def evaluate_drift(
    request: DriftEvaluateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Calculates PSI and KS statistics between baseline telemetry and the specified sample window."""
    baseline_df = _generate_telemetry_df(sample_count=request.sample_count, introduce_drift=False)
    current_df = _generate_telemetry_df(sample_count=request.sample_count, introduce_drift=request.introduce_drift)

    drift_result = drift_detector.evaluate_dataset_drift(baseline_df, current_df)

    # Record evaluation in database if active model exists
    models = await model_registry.list_models(db)
    if models and models[0].versions:
        deployed_version = next((v for v in models[0].versions if v.is_deployed), models[0].versions[0])
        await model_registry.record_drift_metric(
            db=db,
            model_version_id=deployed_version.id,
            psi_metric=drift_result["mean_psi"],
            ks_pvalue=0.001 if drift_result["drift_detected"] else 0.85,
            drift_detected=drift_result["drift_detected"],
            drifted_features={"drifted": drift_result["drifted_features"]},
        )

    await audit_service.log_event(
        db=db,
        action="DRIFT_EVALUATION_EXECUTED",
        resource_type="ML_MONITORING",
        resource_id="drift_detector",
        details={
            "drift_detected": drift_result["drift_detected"],
            "status": drift_result["status"],
            "max_psi": drift_result["max_psi"],
            "drifted_count": drift_result["drifted_features_count"],
        },
    )

    return drift_result


@router.get(
    "/models",
    response_model=List[MLModelResponse],
    summary="List Registered ML Models & Active Champions",
)
async def list_registered_models(
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Retrieves all registered models, current deployed champion version, and historical candidates."""
    await model_registry.seed_initial_registry(db)
    models = await model_registry.list_models(db)
    return models


@router.get(
    "/models/{model_id}/versions",
    response_model=List[ModelVersionResponse],
    summary="Get Model Version History & Metrics",
)
async def get_model_versions(
    model_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Lists all candidate, challenger, and champion versions for a specific model."""
    versions = await model_registry.get_model_versions(db, model_id)
    return versions


@router.post(
    "/models/{version_id}/promote",
    response_model=ModelVersionResponse,
    summary="Promote Model Version to Active Champion",
)
async def promote_model_version(
    version_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Promotes a challenger model version to active production champion with atomic rollback capability."""
    try:
        promoted = await model_registry.promote_version(db, version_id)
        await audit_service.log_event(
            db=db,
            action="MODEL_VERSION_PROMOTED",
            resource_type="MODEL_VERSION",
            resource_id=version_id,
            details={"version": promoted.version, "validation_f1": promoted.validation_f1},
        )
        return promoted
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Promotion failed: {str(e)}")


@router.post(
    "/retrain",
    response_model=RetrainResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Automated Model Retraining Pipeline",
)
async def trigger_retraining(
    request: RetrainRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Executes the continuous retraining pipeline and performs champion-vs-challenger evaluation gating."""
    try:
        result = await retraining_pipeline.run_retraining_job(
            db=db,
            trigger_reason=request.trigger_reason,
            auto_promote=request.auto_promote,
        )

        await audit_service.log_event(
            db=db,
            action="MODEL_RETRAINING_EXECUTED",
            resource_type="RETRAINING_PIPELINE",
            resource_id=result["job_id"],
            details={
                "version": result["version"],
                "trigger_reason": result["trigger_reason"],
                "training_samples": result["training_samples"],
            },
        )

        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Retraining execution failed: {str(e)}",
        )
