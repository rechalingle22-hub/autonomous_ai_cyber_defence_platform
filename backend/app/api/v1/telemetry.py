# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Telemetry ingestion and query API router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path:
        sys.path.insert(0, p)

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.database.session import get_db
from backend.app.models.event import SecurityEvent, EventType, EventSeverity
from backend.app.schemas.common_event import CommonEventSchema
from backend.app.api.websockets.manager import ws_manager

router = APIRouter(prefix="/telemetry", tags=["Telemetry Ingestion"])


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    event_in: CommonEventSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Ingests a normalized security telemetry event.

    Validates schema, persists to event store, and broadcasts event to real-time subscribers.
    """
    event_id = event_in.event_id or str(uuid.uuid4())

    db_event = SecurityEvent(
        id=event_id,
        timestamp=event_in.timestamp,
        event_type=event_in.event_type,
        severity=event_in.severity,
        source_ip=event_in.source_ip,
        destination_ip=event_in.destination_ip,
        source_port=event_in.source_port,
        destination_port=event_in.destination_port,
        protocol=event_in.protocol,
        user_id=event_in.user_id,
        device_id=event_in.device_id,
        raw_payload=event_in.metadata,
        normalized_features=event_in.features,
    )
    db.add(db_event)
    await db.commit()
    await db.refresh(db_event)

    # Broadcast to live dashboard stream
    await ws_manager.broadcast({
        "type": "NEW_TELEMETRY_EVENT",
        "data": {
            "event_id": db_event.id,
            "timestamp": db_event.timestamp.isoformat(),
            "event_type": db_event.event_type.value,
            "source_ip": db_event.source_ip,
            "destination_ip": db_event.destination_ip,
            "severity": db_event.severity.value,
        }
    })

    return {
        "status": "ACCEPTED",
        "event_id": db_event.id,
        "timestamp": db_event.timestamp.isoformat(),
    }


@router.get("/events", response_model=List[dict])
async def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: Optional[EventType] = None,
    severity: Optional[EventSeverity] = None,
    source_ip: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> List[dict]:
    """Retrieves paginated historical telemetry events with optional filters."""
    query = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp))

    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    if severity:
        query = query.where(SecurityEvent.severity == severity)
    if source_ip:
        query = query.where(SecurityEvent.source_ip == source_ip)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()

    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type.value,
            "severity": e.severity.value,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "source_port": e.source_port,
            "destination_port": e.destination_port,
            "protocol": e.protocol,
            "user_id": e.user_id,
            "device_id": e.device_id,
            "features": e.normalized_features,
        }
        for e in events
    ]

