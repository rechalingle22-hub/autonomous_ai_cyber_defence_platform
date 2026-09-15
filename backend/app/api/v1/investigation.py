# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Multi-Agent AI SOC Investigation and Threat Hunting REST API Router."""

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

from backend.app.database.session import get_db
from backend.app.models.investigation import Investigation, InvestigationStatus
from backend.app.models.incident import Incident
from backend.app.investigation.models import (
    InvestigationTriggerRequest,
    HypothesisAddRequest,
    InvestigationResponse,
    InvestigationStatsResponse,
)
from backend.app.investigation.coordinator import investigation_coordinator

router = APIRouter(prefix="/investigations", tags=["Multi-Agent AI SOC Investigation"])


@router.get("", response_model=List[InvestigationResponse])
async def list_investigations(
    incident_id: Optional[str] = None,
    status_filter: Optional[InvestigationStatus] = Query(None, alias="status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[InvestigationResponse]:
    """Lists multi-agent investigations with optional incident and status filters."""
    query = select(Investigation).order_by(desc(Investigation.created_at))

    if incident_id:
        query = query.where(Investigation.incident_id == incident_id)
    if status_filter:
        query = query.where(Investigation.status == status_filter)

    query = query.offset(offset).limit(limit)
    res = await db.execute(query)
    records = res.scalars().all()

    output = []
    for r in records:
        status_str = getattr(r.status, "value", str(r.status))
        output.append(
            InvestigationResponse(
                id=str(r.id),
                incident_id=str(r.incident_id),
                analyst_id=str(r.analyst_id) if r.analyst_id else None,
                status=status_str,
                observed_evidence=r.observed_evidence or {},
                inferred_hypotheses=r.inferred_hypotheses or {},
                agent_scratchpad=r.agent_scratchpad or {},
                executive_summary=r.executive_summary,
                technical_analysis=r.technical_analysis,
                created_at=r.created_at,
                completed_at=r.completed_at,
            )
        )
    return output


@router.post("/trigger", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def trigger_investigation(
    payload: InvestigationTriggerRequest,
    db: AsyncSession = Depends(get_db),
) -> InvestigationResponse:
    """Dispatches the multi-agent AI team (Triage, Evidence Hunter, Forensics, Lead) to investigate an incident."""
    # Look up incident context if stored
    inc_res = await db.execute(select(Incident).where(Incident.id == payload.incident_id))
    inc = inc_res.scalar_one_or_none()

    incident_context: Dict[str, Any] = {
        "id": payload.incident_id,
        "incident_id": payload.incident_id,
        "title": inc.title if inc else f"Ad-hoc Investigation for {payload.incident_id}",
        "severity": getattr(inc.severity, "value", str(inc.severity)) if inc else "HIGH",
        "attack_stage": getattr(inc.attack_stage, "value", str(inc.attack_stage)) if inc else "INITIAL_ACCESS",
        "composite_risk_score": float(inc.composite_risk_score) if inc else 65.0,
    }

    result = await investigation_coordinator.run_investigation(
        incident_context=incident_context,
        analyst_id=payload.analyst_id,
        db_session=db,
    )

    return InvestigationResponse(
        id=result["id"],
        incident_id=result["incident_id"],
        analyst_id=result.get("analyst_id"),
        status=result["status"],
        observed_evidence=result.get("observed_evidence", {}),
        inferred_hypotheses=result.get("inferred_hypotheses", {}),
        agent_scratchpad=result.get("agent_scratchpad", {}),
        executive_summary=result.get("executive_summary"),
        technical_analysis=result.get("technical_analysis"),
        recommended_playbook=result.get("recommended_playbook"),
        false_positive_probability=result.get("false_positive_probability", 0.0),
        created_at=result["created_at"],
        completed_at=result.get("completed_at"),
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
) -> InvestigationResponse:
    """Retrieves full case dossier with segregated evidence and hypotheses."""
    res = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
    inv = res.scalar_one_or_none()

    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )

    status_str = getattr(inv.status, "value", str(inv.status))
    return InvestigationResponse(
        id=str(inv.id),
        incident_id=str(inv.incident_id),
        analyst_id=str(inv.analyst_id) if inv.analyst_id else None,
        status=status_str,
        observed_evidence=inv.observed_evidence or {},
        inferred_hypotheses=inv.inferred_hypotheses or {},
        agent_scratchpad=inv.agent_scratchpad or {},
        executive_summary=inv.executive_summary,
        technical_analysis=inv.technical_analysis,
        created_at=inv.created_at,
        completed_at=inv.completed_at,
    )


@router.post("/{investigation_id}/hypothesize", response_model=InvestigationResponse)
async def add_hypothesis(
    investigation_id: str,
    payload: HypothesisAddRequest,
    db: AsyncSession = Depends(get_db),
) -> InvestigationResponse:
    """Allows a human analyst or secondary agent to record an augmented hypothesis into the case."""
    res = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
    inv = res.scalar_one_or_none()

    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )

    curr_hypotheses = dict(inv.inferred_hypotheses or {})
    items = list(curr_hypotheses.get("items", []))
    new_hyp = {
        "hypothesis_id": f"analyst-hyp-{len(items)+1}",
        "claim": payload.claim,
        "supporting_evidence_ids": payload.supporting_evidence_ids,
        "confidence": payload.confidence,
        "risk_level": payload.risk_level,
        "recommended_action": payload.recommended_action,
    }
    items.append(new_hyp)
    curr_hypotheses["items"] = items
    curr_hypotheses["count"] = len(items)

    inv.inferred_hypotheses = curr_hypotheses
    await db.commit()
    await db.refresh(inv)

    status_str = getattr(inv.status, "value", str(inv.status))
    return InvestigationResponse(
        id=str(inv.id),
        incident_id=str(inv.incident_id),
        analyst_id=str(inv.analyst_id) if inv.analyst_id else None,
        status=status_str,
        observed_evidence=inv.observed_evidence or {},
        inferred_hypotheses=inv.inferred_hypotheses or {},
        agent_scratchpad=inv.agent_scratchpad or {},
        executive_summary=inv.executive_summary,
        technical_analysis=inv.technical_analysis,
        created_at=inv.created_at,
        completed_at=inv.completed_at,
    )


@router.get("/stats/overview", response_model=InvestigationStatsResponse)
async def get_investigation_stats() -> InvestigationStatsResponse:
    """Returns aggregated multi-agent SOC investigation performance and MTTR statistics."""
    stats = investigation_coordinator.get_stats()
    return InvestigationStatsResponse(
        total_investigations=stats["total_investigations"],
        completed_count=stats["completed_count"],
        running_count=stats["running_count"],
        failed_count=stats["failed_count"],
        avg_duration_seconds=stats["avg_duration_seconds"],
        false_positive_rate=stats["false_positive_rate"],
    )

