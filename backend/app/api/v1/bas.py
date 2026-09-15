# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Breach and Attack Simulation (BAS) REST API Router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.schemas.bas import (
    CampaignProfileResponse,
    CampaignExecutionRequest,
    CampaignExecutionResponse,
    CoverageMatrixItemResponse,
    BasMetricsResponse,
)
from backend.app.bas.engine import bas_engine
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/bas", tags=["Autonomous Threat Emulation & Multi-Stage Adversary Simulation (BAS)"])


@router.get(
    "/metrics",
    response_model=BasMetricsResponse,
    summary="Get Global Breach & Attack Simulation Posture Metrics",
)
async def get_bas_metrics() -> Any:
    """Returns overall posture score, detection & prevention rates, and ATT&CK technique counts."""
    return bas_engine.get_metrics()


@router.get(
    "/campaigns",
    response_model=List[CampaignProfileResponse],
    summary="List Curated APT Adversary Campaigns",
)
async def list_campaigns() -> Any:
    """Retrieves full list of curated multi-stage adversary campaigns (APT29, FIN7, Lazarus, BlackCat)."""
    return bas_engine.get_campaigns()


@router.get(
    "/campaigns/{campaign_id}",
    response_model=CampaignProfileResponse,
    summary="Get Specific Adversary Campaign Profile",
)
async def get_campaign(campaign_id: str) -> Any:
    """Retrieves a single campaign profile with full sequential kill-chain stages."""
    try:
        return bas_engine.get_campaign(campaign_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@router.post(
    "/campaigns/execute",
    response_model=CampaignExecutionResponse,
    summary="Execute Non-Destructive Adversary Emulation Run",
)
async def execute_campaign(
    request: CampaignExecutionRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Safely executes multi-stage attack emulation and validates multi-layer detection/prevention."""
    try:
        sim_result = bas_engine.execute_campaign(
            campaign_id=request.campaign_id,
            target_environment=request.target_environment,
            dry_run=request.dry_run,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="ADVERSARY_SIMULATION_EXECUTED",
        resource_type="BAS_SIMULATION",
        resource_id=sim_result["simulation_id"],
        details={
            "campaign_id": sim_result["campaign_id"],
            "posture_score": sim_result["posture_score"],
            "prevention_rate_percent": sim_result["prevention_rate_percent"],
            "detection_rate_percent": sim_result["detection_rate_percent"],
            "verdict": sim_result["summary_verdict"],
            "total_stages": sim_result["total_stages"],
        },
    )

    return sim_result


@router.get(
    "/simulations",
    response_model=List[CampaignExecutionResponse],
    summary="Get Adversary Simulation Run History",
)
async def get_simulations(limit: int = Query(50, ge=1, le=100)) -> Any:
    """Retrieves past emulation runs, stage breakdown, and prevention metrics."""
    return bas_engine.get_simulation_history(limit=limit)


@router.get(
    "/coverage-matrix",
    response_model=List[CoverageMatrixItemResponse],
    summary="Get MITRE ATT&CK Defense Coverage Matrix",
)
async def get_coverage_matrix() -> Any:
    """Retrieves MITRE ATT&CK technique matrix with detection and prevention statuses."""
    return bas_engine.get_coverage_matrix()

