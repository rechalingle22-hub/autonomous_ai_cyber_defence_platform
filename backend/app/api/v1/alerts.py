# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Alerts triage and management API router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path:
        sys.path.insert(0, p)

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.database.session import get_db
from backend.app.models.alert import Alert, AlertSeverity, AlertStatus, DetectionSource
from backend.app.schemas.alert import AlertCreate, AlertResponse, AlertUpdate
from backend.app.auth.rbac import get_current_user
from backend.app.models.user import User
from backend.app.api.websockets.manager import ws_manager
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get("", response_model=List[AlertResponse])
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: Optional[AlertSeverity] = None,
    status_filter: Optional[AlertStatus] = Query(None, alias="status"),
    source: Optional[DetectionSource] = None,
    db: AsyncSession = Depends(get_db),
) -> List[Alert]:
    """Lists security detection alerts with multi-dimensional filtering."""
    query = select(Alert).order_by(desc(Alert.created_at))

    if severity:
        query = query.where(Alert.severity == severity)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if source:
        query = query.where(Alert.detection_source == source)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert_in: AlertCreate,
    db: AsyncSession = Depends(get_db),
) -> Alert:
    """Creates an alert (typically invoked by detection workers or pipeline engines)."""
    alert = Alert(
        event_id=alert_in.event_id,
        incident_id=alert_in.incident_id,
        title=alert_in.title,
        description=alert_in.description,
        detection_source=alert_in.detection_source,
        confidence=alert_in.confidence,
        anomaly_score=alert_in.anomaly_score,
        severity=alert_in.severity,
        mitre_technique_id=alert_in.mitre_technique_id,
        mitre_tactic=alert_in.mitre_tactic,
        contributing_features=alert_in.contributing_features,
        status=AlertStatus.NEW,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    # Broadcast alert to SOC dashboard
    await ws_manager.broadcast({
        "type": "NEW_SECURITY_ALERT",
        "data": {
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity.value,
            "confidence": alert.confidence,
            "detection_source": alert.detection_source.value,
            "mitre_technique_id": alert.mitre_technique_id,
        }
    })

    return alert


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
) -> Alert:
    """Retrieves detailed information for a specific alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    return alert


@router.patch("/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: str,
    update_in: AlertUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Alert:
    """Updates the triage status of an alert (Analyst action)."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    old_status = alert.status.value
    if update_in.status:
        alert.status = update_in.status
    if update_in.incident_id:
        alert.incident_id = update_in.incident_id

    await db.commit()
    await db.refresh(alert)

    await audit_service.log_event(
        db=db,
        action="ALERT_STATUS_UPDATED",
        resource_type="ALERT",
        resource_id=alert.id,
        user_id=current_user.id,
        details={"old_status": old_status, "new_status": alert.status.value},
        ip_address=request.client.host if request.client else None,
    )

    return alert

