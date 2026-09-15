"""Models package initialization and metadata registration."""

from backend.app.models.user import User, UserRole
from backend.app.models.asset import Asset, AssetType, CriticalityLevel, Vulnerability, AssetVulnerability
from backend.app.models.event import SecurityEvent, EventType, EventSeverity
from backend.app.models.alert import Alert, AlertSeverity, AlertStatus, DetectionSource
from backend.app.models.incident import Incident, IncidentStatus, AttackStage, AttackTimeline
from backend.app.models.threat_intel import ThreatIndicator, IndicatorType
from backend.app.models.investigation import Investigation, InvestigationStatus
from backend.app.models.response import ResponseAction, ResponseApproval, ActionType, ActionStatus
from backend.app.models.model_registry import MLModel, ModelVersion, DriftMetric, ModelFamily
from backend.app.models.audit_log import AuditLog
from backend.app.models.report import Report, ReportType, ReportFormat, ReportStatus

__all__ = [
    "User",
    "UserRole",
    "Asset",
    "AssetType",
    "CriticalityLevel",
    "Vulnerability",
    "AssetVulnerability",
    "SecurityEvent",
    "EventType",
    "EventSeverity",
    "Alert",
    "AlertSeverity",
    "AlertStatus",
    "DetectionSource",
    "Incident",
    "IncidentStatus",
    "AttackStage",
    "AttackTimeline",
    "ThreatIndicator",
    "IndicatorType",
    "Investigation",
    "InvestigationStatus",
    "ResponseAction",
    "ResponseApproval",
    "ActionType",
    "ActionStatus",
    "MLModel",
    "ModelVersion",
    "DriftMetric",
    "ModelFamily",
    "AuditLog",
    "Report",
    "ReportType",
    "ReportFormat",
    "ReportStatus",
]


