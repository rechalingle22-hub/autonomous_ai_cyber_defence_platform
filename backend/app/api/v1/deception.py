# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Cyber Deception, Honeytokens & Decoy Honeynet REST API Router."""

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
from backend.app.schemas.deception import (
    HoneytokenDeployRequest,
    HoneytokenResponse,
    HoneytokenTripwireRequest,
    HoneytokenTripwireResponse,
    DecoyInteractRequest,
    DecoyServiceResponse,
    DeceptionMetricsResponse,
)
from backend.app.deception.engine import deception_engine, HoneytokenType
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/deception", tags=["Cyber Deception & Decoy Honeynet"])


@router.get(
    "/metrics",
    response_model=DeceptionMetricsResponse,
    summary="Get Global Deception Posture & Tripwire Metrics",
)
async def get_deception_metrics() -> Any:
    """Returns total deployed honeytokens, tripwire hit rates, and decoy network status."""
    return deception_engine.get_deception_metrics()


@router.get(
    "/tokens",
    response_model=List[HoneytokenResponse],
    summary="List All Active & Tripped Honeytokens",
)
async def list_honeytokens() -> Any:
    """Retrieves all deployed enterprise honeytokens with bait locations and hit stats."""
    return list(deception_engine.honeytokens.values())


@router.post(
    "/tokens/deploy",
    response_model=HoneytokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Deploy New Enterprise Honeytoken",
)
async def deploy_honeytoken(
    request: HoneytokenDeployRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Provisions and plants a realistic honeytoken bait into the target infrastructure."""
    try:
        t_type = HoneytokenType(request.token_type)
    except ValueError:
        valid_types = [t.value for t in HoneytokenType]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid token_type '{request.token_type}'. Valid types: {valid_types}",
        )

    token = deception_engine.deploy_honeytoken(
        token_type=t_type,
        name=request.name,
        bait_path=request.bait_path,
        metadata=request.metadata,
    )

    await audit_service.log_event(
        db=db,
        action="HONEYTOKEN_DEPLOYED",
        resource_type="DECEPTION_HONEYTOKEN",
        resource_id=token["id"],
        details={
            "token_type": token["token_type"],
            "name": token["name"],
            "bait_path": token["bait_path"],
        },
    )

    return token


@router.post(
    "/tokens/tripwire",
    response_model=HoneytokenTripwireResponse,
    summary="Trigger Honeytoken Tripwire (Zero-False-Positive Incident)",
)
async def trigger_honeytoken_tripwire(
    request: HoneytokenTripwireRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Handles an adversary accessing or authenticating with a honeytoken bait."""
    result = deception_engine.trigger_honeytoken_tripwire(
        token_value_or_id=request.token_value_or_id,
        source_ip=request.source_ip,
        user_agent=request.user_agent,
        context=request.context,
    )

    if not result.get("tripwire_triggered"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.get("error", "Honeytoken not recognized."),
        )

    alert = result["alert"]
    await audit_service.log_event(
        db=db,
        action="HONEYTOKEN_TRIPWIRE_BREACH",
        resource_type="SECURITY_INCIDENT",
        resource_id=alert["event_id"],
        details={
            "token_id": alert["token_id"],
            "token_name": alert["token_name"],
            "source_ip": alert["source_ip"],
            "mitre_technique": alert["mitre_technique_id"],
            "recommended_action": alert["recommended_action"],
        },
    )

    return result


@router.post(
    "/tokens/{token_id}/revoke",
    response_model=HoneytokenResponse,
    summary="Revoke Active Honeytoken",
)
async def revoke_honeytoken(
    token_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Revokes a honeytoken from active surveillance."""
    token = deception_engine.revoke_honeytoken(token_id)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Honeytoken '{token_id}' not found.",
        )

    await audit_service.log_event(
        db=db,
        action="HONEYTOKEN_REVOKED",
        resource_type="DECEPTION_HONEYTOKEN",
        resource_id=token_id,
        details={"name": token["name"], "status": "REVOKED"},
    )

    return token


@router.get(
    "/decoys",
    response_model=List[DecoyServiceResponse],
    summary="List Active Decoy Honeynet Services",
)
async def list_decoys() -> Any:
    """Retrieves all active decoy services and their captured interaction telemetry."""
    return list(deception_engine.decoys.values())


@router.post(
    "/decoys/{decoy_id}/interact",
    summary="Simulate Adversary Interaction with Decoy Service",
)
async def interact_with_decoy(
    decoy_id: str,
    request: DecoyInteractRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Simulates an attacker reconnaissance probe or command injection against a decoy micro-service."""
    result = deception_engine.interact_with_decoy(
        decoy_id=decoy_id,
        command_or_payload=request.command_or_payload,
        source_ip=request.source_ip,
    )

    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"],
        )

    entry = result["interaction_entry"]
    await audit_service.log_event(
        db=db,
        action="DECOY_INTERACTION_CAPTURED",
        resource_type="DECOY_SERVICE",
        resource_id=decoy_id,
        details={
            "source_ip": entry["source_ip"],
            "command_or_payload": entry["command_or_payload"],
        },
    )

    return result

