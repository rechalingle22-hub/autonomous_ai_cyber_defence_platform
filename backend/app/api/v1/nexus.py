# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Master SOC Command Nexus REST API Router."""

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
from backend.app.schemas.nexus import (
    MasterPostureResponse,
    EmergencyLockdownRequest,
    EmergencyLockdownResponse,
    LiftLockdownResponse,
    DiagnosticsResponse,
)
from backend.app.nexus.engine import nexus_engine
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/nexus", tags=["Master SOC Command Nexus"])


@router.get(
    "/posture",
    response_model=MasterPostureResponse,
    summary="Get Global Autonomous Cyber Defense Readiness & 24-Subsystem Heartbeat",
)
async def get_master_posture() -> Any:
    """Returns aggregated readiness score, MTTD, MTTR, and real-time health for all 24 security engines."""
    return nexus_engine.get_master_posture()


@router.post(
    "/emergency-lockdown",
    response_model=EmergencyLockdownResponse,
    summary="Trigger Coordinated Platform-Wide Emergency Lockdown",
)
async def trigger_emergency_lockdown(
    payload: EmergencyLockdownRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Executes platform-wide lockdown across Zero-Trust, SOAR, ASM, and Exposure layers."""
    result = nexus_engine.trigger_emergency_lockdown(
        operator=payload.operator or "SOC_COMMANDER",
        reason=payload.reason or "COORDINATED_APT_CONTAINMENT",
    )

    # Log tamper-proof audit event
    try:
        await audit_service.log_event(
            db=db,
            event_type="NEXUS_EMERGENCY_LOCKDOWN_TRIGGERED",
            actor=payload.operator or "SOC_COMMANDER",
            action="EMERGENCY_LOCKDOWN",
            target="ENTERPRISE_NETWORK_PERIMETER",
            details={
                "lockdown_id": result.get("lockdown_id"),
                "reason": payload.reason,
                "readiness_index": result.get("readiness_index"),
                "audit_trail_id": result.get("audit_trail_id"),
            },
            severity="CRITICAL",
        )
    except Exception:
        pass

    return result


@router.post(
    "/lift-lockdown",
    response_model=LiftLockdownResponse,
    summary="Lift Emergency Lockdown and Resume Standard Autonomous Defense",
)
async def lift_emergency_lockdown(
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Restores baseline microsegmentation and standard autonomous defense operations."""
    result = nexus_engine.lift_emergency_lockdown()

    try:
        await audit_service.log_event(
            db=db,
            event_type="NEXUS_EMERGENCY_LOCKDOWN_LIFTED",
            actor="SOC_COMMANDER",
            action="LIFT_LOCKDOWN",
            target="ENTERPRISE_NETWORK_PERIMETER",
            details={"previous_lockdown_id": result.get("previous_lockdown_id")},
            severity="HIGH",
        )
    except Exception:
        pass

    return result


@router.post(
    "/run-diagnostics",
    response_model=DiagnosticsResponse,
    summary="Run Self-Healing Platform Certification Diagnostics",
)
async def run_platform_diagnostics() -> Any:
    """Executes automated diagnostic probe certifying all 24 security engines."""
    return nexus_engine.run_platform_diagnostics()

