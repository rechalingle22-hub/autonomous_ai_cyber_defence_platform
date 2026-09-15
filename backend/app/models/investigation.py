"""Multi-agent AI SOC investigation ORM models."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, DateTime, Enum, JSON, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class InvestigationStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Investigation(Base):
    __tablename__ = "investigations"

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
    analyst_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus),
        default=InvestigationStatus.PENDING,
        nullable=False,
    )

    # Segregated reasoning state (Anti-Hallucination Guardrails)
    observed_evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    inferred_hypotheses: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    agent_scratchpad: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    technical_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="investigations")
    analyst = relationship("User", back_populates="investigations")

