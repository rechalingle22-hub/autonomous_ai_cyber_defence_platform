# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Zero-Trust Adaptive Access Control & Micro-Segmentation REST API Router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.schemas.zerotrust import (
    ContextualAccessEvaluateRequest,
    ContextualAccessEvaluateResponse,
    MicrosegmentationPolicyRequest,
    MicrosegmentationPolicyResponse,
    StepUpChallengeResponse,
    ZeroTrustMetricsResponse,
)
from backend.app.zerotrust.engine import (
    zero_trust_engine,
    ResourceSensitivity,
    AuthAssuranceLevel,
)
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/zerotrust", tags=["Zero-Trust Adaptive Access Control & ZTNA"])


@router.get(
    "/metrics",
    response_model=ZeroTrustMetricsResponse,
    summary="Get Global Zero-Trust Posture Metrics",
)
async def get_zerotrust_metrics() -> Any:
    """Returns average trust score, microsegmentation policy counts, and continuous verification stats."""
    return zero_trust_engine.get_zero_trust_metrics()


@router.post(
    "/evaluate",
    response_model=ContextualAccessEvaluateResponse,
    summary="Contextual Access Decision Evaluation (NIST SP 800-207 PDP)",
)
async def evaluate_access(
    request: ContextualAccessEvaluateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Evaluates contextual access attempt based on multi-dimensional trust score and resource sensitivity."""
    try:
        res_sens = ResourceSensitivity(request.resource_sensitivity)
    except ValueError:
        valid_sens = [s.value for s in ResourceSensitivity]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid resource_sensitivity '{request.resource_sensitivity}'. Valid options: {valid_sens}",
        )

    try:
        auth_lvl = AuthAssuranceLevel(request.auth_level)
    except ValueError:
        valid_auth = [a.value for a in AuthAssuranceLevel]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid auth_level '{request.auth_level}'. Valid options: {valid_auth}",
        )

    result = zero_trust_engine.evaluate_access_request(
        user_id=request.user_id,
        resource_id=request.resource_id,
        resource_sensitivity=res_sens,
        auth_level=auth_lvl,
        device_posture=request.device_posture,
        ueba_anomaly_score=request.ueba_anomaly_score,
        network_context=request.network_context,
        active_incident_link=request.active_incident_link,
        source_subnet=request.source_subnet,
        destination_subnet=request.destination_subnet,
    )

    await audit_service.log_event(
        db=db,
        action="ZEROTRUST_ACCESS_EVALUATED",
        resource_type="ZT_DECISION",
        resource_id=result["evaluation_id"],
        details={
            "user_id": result["user_id"],
            "resource_id": result["resource_id"],
            "trust_score": result["trust_score"],
            "decision": result["decision"],
        },
    )

    return result


@router.get(
    "/policies",
    response_model=List[MicrosegmentationPolicyResponse],
    summary="List Micro-Segmentation Security Policies",
)
async def list_policies() -> Any:
    """Retrieves all active and configured micro-segmentation rules."""
    return list(zero_trust_engine.microsegmentation_policies.values())


@router.post(
    "/policies",
    response_model=MicrosegmentationPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New Micro-Segmentation Policy",
)
async def create_policy(
    request: MicrosegmentationPolicyRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Provisions a new software-defined micro-segmentation rule."""
    if request.action.upper() not in ("ALLOW", "DENY"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy action must be either 'ALLOW' or 'DENY'.",
        )

    policy = zero_trust_engine.create_microsegmentation_policy(
        name=request.name,
        source_subnet=request.source_subnet,
        destination_subnet=request.destination_subnet,
        port_protocol=request.port_protocol,
        action=request.action,
        description=request.description or "",
    )

    await audit_service.log_event(
        db=db,
        action="MICROSEGMENTATION_POLICY_CREATED",
        resource_type="ZT_POLICY",
        resource_id=policy["id"],
        details={
            "name": policy["name"],
            "source_subnet": policy["source_subnet"],
            "destination_subnet": policy["destination_subnet"],
            "action": policy["action"],
        },
    )

    return policy


@router.post(
    "/policies/{policy_id}/toggle",
    response_model=MicrosegmentationPolicyResponse,
    summary="Toggle Micro-Segmentation Policy State",
)
async def toggle_policy_state(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Enables or disables an existing micro-segmentation policy."""
    policy = zero_trust_engine.toggle_policy(policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found.",
        )

    await audit_service.log_event(
        db=db,
        action="MICROSEGMENTATION_POLICY_TOGGLED",
        resource_type="ZT_POLICY",
        resource_id=policy_id,
        details={"is_enabled": policy["is_enabled"]},
    )

    return policy


@router.post(
    "/sessions/{session_id}/step-up",
    response_model=StepUpChallengeResponse,
    summary="Trigger Step-Up MFA Challenge for Session",
)
async def trigger_step_up(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Dispatches a re-authentication challenge to an active user session."""
    challenge = zero_trust_engine.trigger_step_up_challenge(session_id)

    await audit_service.log_event(
        db=db,
        action="STEP_UP_MFA_CHALLENGED",
        resource_type="USER_SESSION",
        resource_id=session_id,
        details={"challenge_id": challenge["challenge_id"]},
    )

    return challenge

