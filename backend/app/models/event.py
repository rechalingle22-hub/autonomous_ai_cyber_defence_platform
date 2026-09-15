"""Security telemetry event ORM model."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, DateTime, Enum, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class EventSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, enum.Enum):
    NETFLOW = "NETFLOW"
    AUTH = "AUTH"
    DNS = "DNS"
    ENDPOINT = "ENDPOINT"
    FIREWALL = "FIREWALL"
    APPLICATION = "APPLICATION"
    SYNTHETIC = "SYNTHETIC"


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    event_type: Mapped[EventType] = mapped_column(Enum(EventType), default=EventType.NETFLOW, nullable=False)
    severity: Mapped[EventSeverity] = mapped_column(
        Enum(EventSeverity),
        default=EventSeverity.INFO,
        nullable=False,
    )
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), default="TCP", nullable=False)

    user_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
    )

    raw_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    normalized_features: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="events")
    alerts = relationship("Alert", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_security_events_ts_src_dst", "timestamp", "source_ip", "destination_ip"),
    )

