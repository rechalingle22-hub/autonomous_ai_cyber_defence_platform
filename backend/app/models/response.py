"""Response action simulation and human-in-the-loop approval ORM models."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Float, Boolean, DateTime, Enum, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class ActionType(str, enum.Enum):
    ISOLATE_HOST = "ISOLATE_HOST"
    BLOCK_IP = "BLOCK_IP"
    REVOKE_SESSION = "REVOKE_SESSION"
    THROTTLE_BANDWIDTH = "THROTTLE_BANDWIDTH"
    INCREASE_MONITORING = "INCREASE_MONITORING"
    SIMULATE_RECOVERY = "SIMULATE_RECOVERY"


class ActionStatus(str, enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class ResponseAction(Base):
    __tablename__ = "response_actions"

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
    action_type: Mapped[ActionType] = mapped_column(Enum(ActionType), nullable=False)
    target_entity: Mapped[str] = mapped_column(String(128), nullable=False)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[ActionStatus] = mapped_column(
        Enum(ActionStatus),
        default=ActionStatus.PENDING_APPROVAL,
        nullable=False,
    )

    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    risk_impact_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="response_actions")
    approvals = relationship("ResponseApproval", back_populates="response_action", cascade="all, delete-orphan")


class ResponseApproval(Base):
    __tablename__ = "response_approvals"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    response_action_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("response_actions.id", ondelete="CASCADE"),
        nullable=False,
    )
    approved_by_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)  # APPROVED or REJECTED
    comments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    response_action = relationship("ResponseAction", back_populates="approvals")

