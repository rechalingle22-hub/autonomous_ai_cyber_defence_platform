# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Incident and Attack Timeline ORM models."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List  # type: ignore
from sqlalchemy import String, Float, DateTime, Enum, ForeignKey, Text  # type: ignore
from sqlalchemy.orm import Mapped, mapped_column, relationship  # type: ignore

try:
    from ..database.session import Base  # type: ignore
    from .alert import AlertSeverity  # type: ignore
except (ImportError, ValueError):
    from backend.app.database.session import Base  # type: ignore
    from backend.app.models.alert import AlertSeverity  # type: ignore


class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class AttackStage(str, enum.Enum):
    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity),
        default=AlertSeverity.HIGH,
        nullable=False,
    )
    composite_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # 0 to 100
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus),
        default=IncidentStatus.OPEN,
        nullable=False,
    )
    attack_stage: Mapped[AttackStage] = mapped_column(
        Enum(AttackStage),
        default=AttackStage.INITIAL_ACCESS,
        nullable=False,
    )

    primary_asset_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
    )

    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    primary_asset = relationship("Asset", back_populates="incidents")
    alerts = relationship("Alert", back_populates="incident")
    timeline_entries = relationship("AttackTimeline", back_populates="incident", cascade="all, delete-orphan")
    investigations = relationship("Investigation", back_populates="incident", cascade="all, delete-orphan")
    response_actions = relationship("ResponseAction", back_populates="incident", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="incident", cascade="all, delete-orphan")


class AttackTimeline(Base):
    __tablename__ = "attack_timelines"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_summary: Mapped[str] = mapped_column(String(512), nullable=False)
    entity: Mapped[str] = mapped_column(String(128), nullable=False)
    detection_source: Mapped[str] = mapped_column(String(64), nullable=False)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[AlertSeverity] = mapped_column(Enum(AlertSeverity), default=AlertSeverity.MEDIUM)

    # Relationships
    incident = relationship("Incident", back_populates="timeline_entries")

