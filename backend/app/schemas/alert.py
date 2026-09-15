"""Alert schemas for detection outputs and dashboard triage."""

from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from backend.app.models.alert import AlertSeverity, AlertStatus, DetectionSource


class AlertCreate(BaseModel):
    event_id: Optional[str] = None
    incident_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    detection_source: DetectionSource = DetectionSource.XGBOOST
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    contributing_features: Dict[str, Any] = Field(default_factory=dict)


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    incident_id: Optional[str] = None


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: Optional[str] = None
    incident_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    detection_source: DetectionSource
    confidence: float
    anomaly_score: float
    severity: AlertSeverity
    status: AlertStatus
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    contributing_features: Dict[str, Any]
    created_at: datetime
