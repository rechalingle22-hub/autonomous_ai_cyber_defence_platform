"""Asset, Host, and Vulnerability ORM models."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Float, DateTime, Enum, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class AssetType(str, enum.Enum):
    SERVER = "SERVER"
    ENDPOINT = "ENDPOINT"
    ROUTER = "ROUTER"
    FIREWALL = "FIREWALL"
    DATABASE = "DATABASE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"


class CriticalityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    hostname: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType), default=AssetType.SERVER, nullable=False)
    criticality: Mapped[CriticalityLevel] = mapped_column(
        Enum(CriticalityLevel),
        default=CriticalityLevel.MEDIUM,
        nullable=False,
    )
    owner: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    asset_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    vulnerabilities = relationship("AssetVulnerability", back_populates="asset")
    events = relationship("SecurityEvent", back_populates="asset")
    incidents = relationship("Incident", back_populates="primary_asset")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False)
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    severity: Mapped[CriticalityLevel] = mapped_column(Enum(CriticalityLevel), default=CriticalityLevel.MEDIUM)
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    assets = relationship("AssetVulnerability", back_populates="vulnerability")


class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    asset = relationship("Asset", back_populates="vulnerabilities")
    vulnerability = relationship("Vulnerability", back_populates="assets")

