# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Incident and attack timeline schemas."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from datetime import datetime
from typing import Optional, List  # type: ignore
from pydantic import BaseModel, Field, ConfigDict  # type: ignore

try:
    from ..models.alert import AlertSeverity  # type: ignore
    from ..models.incident import IncidentStatus, AttackStage  # type: ignore
except (ImportError, ValueError):
    from backend.app.models.alert import AlertSeverity  # type: ignore
    from backend.app.models.incident import IncidentStatus, AttackStage  # type: ignore


class AttackTimelineCreate(BaseModel):
    timestamp: datetime
    event_summary: str
    entity: str
    detection_source: str
    mitre_technique: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.MEDIUM


class AttackTimelineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    timestamp: datetime
    event_summary: str
    entity: str
    detection_source: str
    mitre_technique: Optional[str] = None
    severity: AlertSeverity


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.HIGH
    composite_risk_score: float = Field(default=50.0, ge=0.0, le=100.0)
    primary_asset_id: Optional[str] = None
    attack_stage: AttackStage = AttackStage.INITIAL_ACCESS


class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    composite_risk_score: Optional[float] = None
    attack_stage: Optional[AttackStage] = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    severity: AlertSeverity
    composite_risk_score: float
    status: IncidentStatus
    attack_stage: AttackStage
    primary_asset_id: Optional[str] = None
    start_time: datetime
    end_time: Optional[datetime] = None
    created_at: datetime
    timeline_entries: List[AttackTimelineResponse] = []
