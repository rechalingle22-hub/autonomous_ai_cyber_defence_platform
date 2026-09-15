# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Security Report & Forensic Dossier ORM Models."""


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
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, DateTime, Enum, ForeignKey, Text, JSON  # type: ignore
from sqlalchemy.orm import Mapped, mapped_column, relationship  # type: ignore
from backend.app.database.session import Base  # type: ignore


class ReportType(str, enum.Enum):
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    TECHNICAL_FORENSIC_DOSSIER = "TECHNICAL_FORENSIC_DOSSIER"
    INCIDENT_POST_MORTEM = "INCIDENT_POST_MORTEM"
    COMPLIANCE_AUDIT = "COMPLIANCE_AUDIT"


class ReportFormat(str, enum.Enum):
    HTML = "HTML"
    MARKDOWN = "MARKDOWN"
    JSON = "JSON"
    CSV = "CSV"


class ReportStatus(str, enum.Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Report(Base):
    __tablename__ = "security_reports"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[ReportType] = mapped_column(
        Enum(ReportType),
        default=ReportType.EXECUTIVE_SUMMARY,
        nullable=False,
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat),
        default=ReportFormat.HTML,
        nullable=False,
    )
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus),
        default=ReportStatus.COMPLETED,
        nullable=False,
    )

    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
    )
    generated_by_user_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    content: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    incident = relationship("Incident", back_populates="reports", foreign_keys=[incident_id])  # type: ignore
    generated_by = relationship("User", back_populates="reports", foreign_keys=[generated_by_user_id])  # type: ignore
