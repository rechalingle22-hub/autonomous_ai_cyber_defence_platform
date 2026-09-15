# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Incidents and attack timeline management API router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List, Optional, Dict, Any  # type: ignore
from fastapi import APIRouter, Depends, HTTPException, Query, status  # type: ignore
from sqlalchemy import select, desc  # type: ignore
from sqlalchemy.orm import selectinload  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

try:
    from ...database.session import get_db  # type: ignore
    from ...models.incident import Incident, IncidentStatus, AttackStage, AttackTimeline  # type: ignore
    from ...models.alert import Alert, AlertSeverity  # type: ignore
    from ...schemas.incident import (  # type: ignore
        IncidentCreate,
        IncidentResponse,
        IncidentUpdate,
        AttackTimelineCreate,
        AttackTimelineResponse,
    )
    from ..websockets.manager import ws_manager  # type: ignore
except (ImportError, ValueError):
    from backend.app.database.session import get_db  # type: ignore
    from backend.app.models.incident import Incident, IncidentStatus, AttackStage, AttackTimeline  # type: ignore
    from backend.app.models.alert import Alert, AlertSeverity  # type: ignore
    from backend.app.schemas.incident import (  # type: ignore
        IncidentCreate,
        IncidentResponse,
        IncidentUpdate,
        AttackTimelineCreate,
        AttackTimelineResponse,
    )
    from backend.app.api.websockets.manager import ws_manager  # type: ignore
from backend.app.database.session import get_db
from backend.app.models.incident import Incident, IncidentStatus, AttackStage, AttackTimeline
from backend.app.models.alert import Alert, AlertSeverity
from backend.app.schemas.incident import (
    IncidentCreate,
    IncidentResponse,
    IncidentUpdate,
    AttackTimelineCreate,
    AttackTimelineResponse,
)
from backend.app.api.websockets.manager import ws_manager

router = APIRouter(prefix="/incidents", tags=["Security Incidents"])


@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: Optional[AlertSeverity] = None,
    status_filter: Optional[IncidentStatus] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
) -> List[Incident]:
    """Retrieves paginated incidents ordered by risk score and creation time."""
    query = (
        select(Incident)
        .options(selectinload(Incident.timeline_entries))
        .order_by(desc(Incident.composite_risk_score), desc(Incident.created_at))
    )

    if severity:
        query = query.where(Incident.severity == severity)
    if status_filter:
        query = query.where(Incident.status == status_filter)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_in: IncidentCreate,
    db: AsyncSession = Depends(get_db),
) -> Incident:
    """Creates a new correlated incident."""
    incident = Incident(
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        composite_risk_score=incident_in.composite_risk_score,
        primary_asset_id=incident_in.primary_asset_id,
        attack_stage=incident_in.attack_stage,
        status=IncidentStatus.OPEN,
    )
    db.add(incident)
    await db.commit()

    # Re-query with timeline entries loaded
    stmt = select(Incident).options(selectinload(Incident.timeline_entries)).where(Incident.id == incident.id)
    res = await db.execute(stmt)
    full_incident = res.scalar_one()

    # Broadcast to dashboard
    await ws_manager.broadcast({
        "type": "NEW_SECURITY_INCIDENT",
        "data": {
            "id": full_incident.id,
            "title": full_incident.title,
            "severity": full_incident.severity.value,
            "risk_score": full_incident.composite_risk_score,
            "stage": full_incident.attack_stage.value,
        }
    })

    return full_incident


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
) -> Incident:
    """Retrieves detailed incident record including chronological attack timeline entries."""
    query = (
        select(Incident)
        .options(selectinload(Incident.timeline_entries))
        .where(Incident.id == incident_id)
    )
    result = await db.execute(query)
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return incident


@router.post("/{incident_id}/timeline", response_model=AttackTimelineResponse, status_code=status.HTTP_201_CREATED)
async def add_timeline_entry(
    incident_id: str,
    entry_in: AttackTimelineCreate,
    db: AsyncSession = Depends(get_db),
) -> AttackTimeline:
    """Appends an event step to an incident's reconstructed attack timeline."""
    incident_result = await db.execute(select(Incident).where(Incident.id == incident_id))
    if not incident_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    timeline_entry = AttackTimeline(
        incident_id=incident_id,
        timestamp=entry_in.timestamp,
        event_summary=entry_in.event_summary,
        entity=entry_in.entity,
        detection_source=entry_in.detection_source,
        mitre_technique=entry_in.mitre_technique,
        severity=entry_in.severity,
    )
    db.add(timeline_entry)
    await db.commit()
    await db.refresh(timeline_entry)

    # Broadcast timeline addition
    await ws_manager.broadcast({
        "type": "TIMELINE_EVENT_ADDED",
        "data": {
            "incident_id": incident_id,
            "summary": timeline_entry.event_summary,
            "entity": timeline_entry.entity,
            "timestamp": timeline_entry.timestamp.isoformat(),
        }
    })

    return timeline_entry


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    update_in: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
) -> Incident:
    """Updates incident status, composite risk score, or attack stage."""
    query = (
        select(Incident)
        .options(selectinload(Incident.timeline_entries))
        .where(Incident.id == incident_id)
    )
    result = await db.execute(query)
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    if update_in.status is not None:
        incident.status = update_in.status
    if update_in.composite_risk_score is not None:
        incident.composite_risk_score = update_in.composite_risk_score
    if update_in.attack_stage is not None:
        incident.attack_stage = update_in.attack_stage

    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/{incident_id}/timeline", response_model=List[AttackTimelineResponse])
async def get_incident_timeline(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
) -> List[AttackTimeline]:
    """Retrieves chronological attack timeline entries for an incident."""
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    if not res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    query = (
        select(AttackTimeline)
        .where(AttackTimeline.incident_id == incident_id)
        .order_by(AttackTimeline.timestamp.asc())
    )
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/correlate", status_code=status.HTTP_200_OK)
async def trigger_alert_correlation(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Scans unassigned security alerts and correlates them into persistent multi-stage incidents."""
    stmt = (
        select(Alert)
        .where(Alert.incident_id.is_(None))
        .order_by(Alert.created_at.asc())
        .limit(limit)
    )
    res = await db.execute(stmt)
    unassigned = list(res.scalars().all())

    if not unassigned:
        return {
            "status": "success",
            "message": "No unassigned alerts found to correlate.",
            "processed_alerts": 0,
            "results": [],
        }

    alert_dicts = []
    for a in unassigned:
        ad = {
            "id": a.id,
            "title": a.title,
            "description": a.description,
            "detection_source": a.detection_source.value if hasattr(a.detection_source, "value") else str(a.detection_source),
            "confidence": a.confidence,
            "anomaly_score": a.anomaly_score,
            "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
            "attack_type": a.mitre_tactic or a.title,
            "timestamp": a.created_at.isoformat() if a.created_at else None,
            "source_ip": a.contributing_features.get("source_ip") if isinstance(a.contributing_features, dict) else None,
            "destination_ip": a.contributing_features.get("destination_ip") if isinstance(a.contributing_features, dict) else None,
            "user_id": a.contributing_features.get("user_id") if isinstance(a.contributing_features, dict) else None,
        }
        alert_dicts.append(ad)

    try:
        from ...correlation.engine import correlation_engine  # type: ignore
    except (ImportError, ValueError):
        from backend.app.correlation.engine import correlation_engine  # type: ignore
    from backend.app.correlation.engine import correlation_engine
    results = await correlation_engine.correlate_batch(alert_dicts, db_session=db)
    return {
        "status": "success",
        "processed_alerts": len(alert_dicts),
        "results": results,
    }


