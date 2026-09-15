# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Cyber Threat Exposure & Attack Path Validation (APV) REST API Router."""

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
from backend.app.schemas.exposure import (
    CrownJewelResponse,
    AttackPathResponse,
    ChokePointResponse,
    ChokePointRemediationRequest,
    ChokePointRemediationResponse,
    ExposureMetricsResponse,
)
from backend.app.exposure.engine import exposure_engine
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/exposure", tags=["Cyber Threat Exposure & Attack Path Validation (APV)"])


@router.get(
    "/metrics",
    response_model=ExposureMetricsResponse,
    summary="Get Global Threat Exposure & Attack Path Metrics",
)
async def get_exposure_metrics() -> Any:
    """Returns overall path resilience index, active vs severed paths, and choke point counts."""
    return exposure_engine.get_metrics()


@router.get(
    "/crown-jewels",
    response_model=List[CrownJewelResponse],
    summary="List Enterprise Crown Jewel Assets",
)
async def list_crown_jewels() -> Any:
    """Retrieves high-value critical assets (PII vault, Domain Controller, Cloud KMS, CI/CD)."""
    return exposure_engine.get_crown_jewels()


@router.get(
    "/attack-paths",
    response_model=List[AttackPathResponse],
    summary="List Multi-Hop Attack Paths to Crown Jewels",
)
async def list_attack_paths() -> Any:
    """Retrieves discovered directed attack paths from external ingress to internal targets."""
    return exposure_engine.get_attack_paths()


@router.get(
    "/choke-points",
    response_model=List[ChokePointResponse],
    summary="List Graph Choke Points (Minimal Cut Sets)",
)
async def list_choke_points() -> Any:
    """Retrieves high-leverage graph bottlenecks ranked by path disruption efficiency."""
    return exposure_engine.get_choke_points()


@router.post(
    "/choke-points/remediate",
    response_model=ChokePointRemediationResponse,
    summary="Simulate Choke Point Remediation & Sever Attack Paths",
)
async def remediate_choke_point(
    request: ChokePointRemediationRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Applies a zero-trust policy cut, immediately severing all intersecting multi-hop attack paths."""
    try:
        result = exposure_engine.remediate_choke_point(request.choke_point_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="CHOKE_POINT_REMEDIATED",
        resource_type="EXPOSURE_CHOKE_POINT",
        resource_id=request.choke_point_id,
        details={
            "choke_point_id": request.choke_point_id,
            "severed_paths_count": result["severed_paths_count"],
            "new_resilience_index": result["new_resilience_index"],
        },
    )

    return result


@router.post(
    "/reset",
    summary="Reset Exposure Graph Remediations to Baseline",
)
async def reset_exposure_graph() -> Any:
    """Resets all choke point remediations to restore the baseline exposure topology."""
    exposure_engine.reset_remediations()
    return {"message": "Exposure graph remediations reset to baseline", "status": "RESET_SUCCESS"}

