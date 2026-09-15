"""Security Alert ORM model."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Float, DateTime, Enum, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class DetectionSource(str, enum.Enum):
    ISOLATION_FOREST = "ISOLATION_FOREST"
    AUTOENCODER = "AUTOENCODER"
    RANDOM_FOREST = "RANDOM_FOREST"
    XGBOOST = "XGBOOST"
    LSTM = "LSTM"
    UEBA = "UEBA"
    THREAT_INTEL = "THREAT_INTEL"
    SIGNATURE = "SIGNATURE"


class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    event_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("security_events.id", ondelete="SET NULL"),
        nullable=True,
    )
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    detection_source: Mapped[DetectionSource] = mapped_column(
        Enum(DetectionSource),
        default=DetectionSource.XGBOOST,
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity),
        default=AlertSeverity.MEDIUM,
        nullable=False,
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus),
        default=AlertStatus.NEW,
        nullable=False,
    )

    # MITRE ATT&CK Mapping
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Explainable AI (XAI) feature factor contributions
    contributing_features: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )

    # Relationships
    event = relationship("SecurityEvent", back_populates="alerts")
    incident = relationship("Incident", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_severity_status", "severity", "status"),
    )

