# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Security Report and Dossier Pydantic schemas."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict

from backend.app.models.report import ReportType, ReportFormat, ReportStatus  # type: ignore


class ReportGenerateRequest(BaseModel):
    """Payload to request the generation of a security report or incident dossier."""

    title: Optional[str] = Field(
        default=None,
        description="Optional custom report title. If omitted, an automated title is synthesized.",
    )
    report_type: ReportType = Field(
        default=ReportType.EXECUTIVE_SUMMARY,
        description="Type of report: EXECUTIVE_SUMMARY, TECHNICAL_FORENSIC_DOSSIER, INCIDENT_POST_MORTEM, COMPLIANCE_AUDIT",
    )
    format: ReportFormat = Field(
        default=ReportFormat.HTML,
        description="Output serialization format: HTML, MARKDOWN, JSON, CSV",
    )
    incident_id: Optional[str] = Field(
        default=None,
        description="Target incident UUID to report on. If omitted, generates a platform-wide security posture report.",
    )
    include_xai: bool = Field(
        default=True,
        description="Include TreeSHAP feature attributions and explainability breakdown.",
    )
    include_soar: bool = Field(
        default=True,
        description="Include SOAR containment actions and playbook execution traces.",
    )
    include_evidence: bool = Field(
        default=True,
        description="Include cryptographically verified observed evidence items.",
    )
    include_mitre: bool = Field(
        default=True,
        description="Include MITRE ATT&CK kill-chain mapping and technique tactics.",
    )


class ReportResponse(BaseModel):
    """Metadata response for a security report."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    report_type: ReportType
    format: ReportFormat
    status: ReportStatus
    incident_id: Optional[str] = None
    generated_by_user_id: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    file_size_bytes: int = 0
    created_at: datetime


class ReportDetailResponse(ReportResponse):
    """Detailed response containing complete rendered content."""

    content: str

