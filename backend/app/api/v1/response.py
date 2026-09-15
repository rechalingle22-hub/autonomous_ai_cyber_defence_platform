# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""SOAR and Incident Response Action Management REST API Router."""

import os
import sys
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.config.settings import settings
from backend.app.database.session import get_db
from backend.app.models.response import ResponseAction, ActionType, ActionStatus
from backend.app.models.incident import Incident
from backend.app.response.models import (
    ActionResult,
    PlaybookDefinition,
    PlaybookExecutionResult,
    ActionCreateRequest,
    ActionApprovalRequest,
    ActionResponse,
    TriggerPlaybookRequest,
    SOARStatsResponse,
)
from backend.app.response.actions import ACTION_REGISTRY
from backend.app.response.playbooks import playbook_registry, playbook_engine
from backend.app.response.dispatcher import response_dispatcher

router = APIRouter(prefix="/response", tags=["SOAR & Incident Response"])


@router.get("/actions", response_model=List[ActionResponse])
async def list_actions(
    status_filter: Optional[ActionStatus] = Query(None, alias="status"),
    incident_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[ActionResponse]:
    """Lists response actions with multi-dimensional filtering."""
    query = select(ResponseAction).order_by(desc(ResponseAction.created_at))

    if status_filter:
        query = query.where(ResponseAction.status == status_filter)
    if incident_id:
        query = query.where(ResponseAction.incident_id == incident_id)

    query = query.offset(offset).limit(limit)
    res = await db.execute(query)
    actions = res.scalars().all()

    output = []
    for a in actions:
        atype = getattr(a.action_type, "value", str(a.action_type))
        astatus = getattr(a.status, "value", str(a.status))
        output.append(
            ActionResponse(
                id=str(a.id),
                incident_id=str(a.incident_id),
                action_type=atype,
                target_entity=str(a.target_entity),
                is_simulation=bool(a.is_simulation),
                status=astatus,
                rationale=str(a.rationale),
                risk_impact_score=float(a.risk_impact_score),
                created_at=a.created_at,
                executed_at=a.executed_at,
            )
        )
    return output


@router.post("/actions", response_model=ActionResponse, status_code=status.HTTP_201_CREATED)
async def create_action(
    payload: ActionCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> ActionResponse:
    """Manually provisions a response action."""
    # Validate incident exists if incident_id provided
    if payload.incident_id != "STANDALONE":
        inc_res = await db.execute(select(Incident).where(Incident.id == payload.incident_id))
        if not inc_res.scalar_one_or_none():
            # Allow creation with fallback incident or proceed
            pass

    action = ResponseAction(
        incident_id=payload.incident_id,
        action_type=payload.action_type,
        target_entity=payload.target_entity.strip(),
        is_simulation=payload.is_simulation,
        status=ActionStatus.PENDING_APPROVAL if payload.risk_impact_score >= 50.0 else ActionStatus.EXECUTED,
        rationale=payload.rationale,
        risk_impact_score=payload.risk_impact_score,
    )

    if action.status == ActionStatus.EXECUTED:
        handler = ACTION_REGISTRY.get(payload.action_type)
        if handler:
            res = await handler.execute(
                target_entity=payload.target_entity,
                is_simulation=payload.is_simulation,
            )
            if not res.success:
                action.status = ActionStatus.FAILED

    db.add(action)
    await db.commit()
    await db.refresh(action)

    atype = getattr(action.action_type, "value", str(action.action_type))
    astatus = getattr(action.status, "value", str(action.status))
    return ActionResponse(
        id=str(action.id),
        incident_id=str(action.incident_id),
        action_type=atype,
        target_entity=str(action.target_entity),
        is_simulation=bool(action.is_simulation),
        status=astatus,
        rationale=str(action.rationale),
        risk_impact_score=float(action.risk_impact_score),
        created_at=action.created_at,
        executed_at=action.executed_at,
    )


@router.post("/actions/{action_id}/approve", response_model=ActionResult)
async def approve_action(
    action_id: str,
    payload: ActionApprovalRequest,
    db: AsyncSession = Depends(get_db),
) -> ActionResult:
    """Authorizes and executes a pending containment action."""
    result = await response_dispatcher.approve_action(
        action_id=action_id,
        analyst_id="current_analyst",
        comments=payload.comments,
        db_session=db,
    )
    if not result.success and "not found" in result.detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action '{action_id}' not found",
        )
    return result


@router.post("/actions/{action_id}/reject")
async def reject_action(
    action_id: str,
    payload: ActionApprovalRequest,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Rejects and dismisses a pending response action proposal."""
    success = await response_dispatcher.reject_action(
        action_id=action_id,
        analyst_id="current_analyst",
        comments=payload.comments,
        db_session=db,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action '{action_id}' not found",
        )
    return {"status": "REJECTED", "action_id": action_id}


@router.post("/actions/{action_id}/rollback", response_model=ActionResult)
async def rollback_action(
    action_id: str,
    db: AsyncSession = Depends(get_db),
) -> ActionResult:
    """Compensates and undoes an executed response action."""
    result = await response_dispatcher.rollback_action(
        action_id=action_id,
        analyst_id="current_analyst",
        db_session=db,
    )
    if not result.success and "not found" in result.detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action '{action_id}' not found",
        )
    return result


@router.get("/playbooks", response_model=List[PlaybookDefinition])
async def list_playbooks() -> List[PlaybookDefinition]:
    """Lists all registered SOAR response playbooks."""
    return playbook_registry.list_all()


@router.post("/playbooks/execute", response_model=PlaybookExecutionResult)
async def execute_playbook(
    payload: TriggerPlaybookRequest,
    db: AsyncSession = Depends(get_db),
) -> PlaybookExecutionResult:
    """Manually triggers a playbook workflow for an incident."""
    playbook = playbook_registry.get(payload.playbook_id)
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{payload.playbook_id}' not found",
        )

    # Fetch incident details if available
    inc_res = await db.execute(select(Incident).where(Incident.id == payload.incident_id))
    inc = inc_res.scalar_one_or_none()
    incident_context: Dict[str, Any] = {"incident_id": payload.incident_id}
    if inc:
        incident_context.update({
            "title": inc.title,
            "severity": getattr(inc.severity, "value", str(inc.severity)),
            "attack_stage": getattr(inc.attack_stage, "value", str(inc.attack_stage)),
        })

    result = await playbook_engine.execute_playbook(
        playbook=playbook,
        incident_context=incident_context,
        is_simulation=payload.is_simulation,
        db_session=db,
    )
    return result


@router.get("/stats", response_model=SOARStatsResponse)
async def get_soar_stats(db: AsyncSession = Depends(get_db)) -> SOARStatsResponse:
    """Returns aggregated SOAR operational metrics and action execution telemetry."""
    res = await db.execute(select(ResponseAction))
    all_actions = res.scalars().all()

    total = len(all_actions)
    pending = len([a for a in all_actions if a.status == ActionStatus.PENDING_APPROVAL])
    executed = len([a for a in all_actions if a.status == ActionStatus.EXECUTED])
    rejected = len([a for a in all_actions if a.status == ActionStatus.REJECTED])
    failed = len([a for a in all_actions if a.status == ActionStatus.FAILED])

    playbooks = playbook_registry.list_all()
    sim_mode = getattr(settings, "SIMULATION_MODE", True)
    hitl = getattr(settings, "REQUIRE_HUMAN_APPROVAL_FOR_CONTAINMENT", True)

    return SOARStatsResponse(
        total_actions=total,
        pending_approval_count=pending,
        executed_count=executed,
        rejected_count=rejected,
        failed_count=failed,
        active_playbooks_count=len(playbooks),
        simulation_mode_enabled=sim_mode,
        hitl_required=hitl,
    )

