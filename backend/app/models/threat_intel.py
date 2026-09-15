"""Threat Intelligence (IOC) ORM models."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Enum, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.database.session import Base


class IndicatorType(str, enum.Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    SHA256 = "SHA256"
    MD5 = "MD5"
    URL = "URL"
    CVE = "CVE"


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    indicator_type: Mapped[IndicatorType] = mapped_column(Enum(IndicatorType), nullable=False)
    indicator_value: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    reputation_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)  # 0 (clean) to 100 (malicious)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="LOCAL_INTEL", nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

