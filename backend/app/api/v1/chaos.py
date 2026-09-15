# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Security Chaos Engineering & Adversarial Resilience REST API Router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

from backend.app.database.session import get_db  # type: ignore
from backend.app.schemas.chaos import (  # type: ignore
    ChaosInjectRequest,
    ChaosExperimentResponse,
    ChaosStatusResponse,
    AdversarialEvaluateRequest,
    AdversarialEvaluateResponse,
)
from backend.app.chaos.engine import chaos_engine, ChaosType  # type: ignore
from backend.app.audit.service import audit_service  # type: ignore
from ml.adversarial.evasion_evaluator import adversarial_evaluator  # type: ignore

router = APIRouter(prefix="/chaos", tags=["Security Chaos Engineering & Adversarial Resilience"])


@router.get(
    "/status",
    response_model=ChaosStatusResponse,
    summary="Get System Resilience Score & Chaos Status",
)
async def get_chaos_status() -> Any:
    """Returns composite resilience score (0-100%), active fault injections, and MTTR metrics."""
    return chaos_engine.calculate_resilience_score()


@router.get(
    "/experiments",
    response_model=List[ChaosExperimentResponse],
    summary="List Active & Historical Chaos Experiments",
)
async def list_chaos_experiments() -> Any:
    """Retrieves all active and historical chaos experiments."""
    return list(chaos_engine.active_experiments.values()) + chaos_engine.history


@router.post(
    "/inject",
    response_model=ChaosExperimentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Inject Controlled Operational Fault",
)
async def inject_chaos_experiment(
    request: ChaosInjectRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Initiates a controlled, reversible fault injection with automatic lease timeout."""
    try:
        exp_type = ChaosType(request.experiment_type)
    except ValueError:
        valid_types = [t.value for t in ChaosType]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid experiment_type '{request.experiment_type}'. Valid types: {valid_types}",
        )

    experiment = chaos_engine.inject_chaos(
        experiment_type=exp_type,
        duration_seconds=request.duration_seconds,
        params=request.params,
    )

    await audit_service.log_event(
        db=db,
        action="CHAOS_FAULT_INJECTED",
        resource_type="CHAOS_EXPERIMENT",
        resource_id=experiment["id"],
        details={
            "experiment_type": experiment["experiment_type"],
            "duration_seconds": experiment["duration_seconds"],
            "params": experiment["params"],
        },
    )

    return experiment


@router.post(
    "/recover",
    response_model=List[ChaosExperimentResponse],
    summary="Recover Chaos Experiment & Restore Steady State",
)
async def recover_chaos(
    payload: Optional[Dict[str, str]] = None,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Immediately recovers a specific chaos experiment or all active experiments."""
    exp_id = payload.get("experiment_id") if payload else None

    if exp_id and exp_id != "ALL":
        recovered_exp = chaos_engine.recover_experiment(exp_id, reason="MANUAL_ABORT")
        if not recovered_exp:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Active chaos experiment '{exp_id}' not found.",
            )
        recovered_list = [recovered_exp]
    else:
        recovered_list = chaos_engine.recover_all(reason="MANUAL_ABORT_ALL")

    await audit_service.log_event(
        db=db,
        action="CHAOS_RECOVERED",
        resource_type="CHAOS_ENGINE",
        resource_id=exp_id or "ALL",
        details={"recovered_count": len(recovered_list)},
    )

    return recovered_list


@router.post(
    "/adversarial/evaluate",
    response_model=AdversarialEvaluateResponse,
    summary="Evaluate Multi-Model Adversarial Evasion Robustness",
)
async def evaluate_adversarial_robustness(
    request: AdversarialEvaluateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Evaluates evasion success rate and Adversarial Robustness Index (ARI) across all active ML models."""
    try:
        results = adversarial_evaluator.evaluate_ensemble_robustness(
            clean_df=None,
            epsilon=request.perturbation_epsilon,
        )

        await audit_service.log_event(
            db=db,
            action="ADVERSARIAL_EVALUATION_COMPLETED",
            resource_type="ML_ADVERSARIAL",
            resource_id="ensemble",
            details={
                "perturbation_epsilon": results["perturbation_epsilon"],
                "ensemble_ari": results["ensemble_adversarial_robustness_index"],
                "ensemble_grade": results["ensemble_robustness_grade"],
            },
        )

        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Adversarial evaluation failed: {str(e)}",
        )

