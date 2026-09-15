# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Security Reporting Orchestration Engine."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import Optional, Dict, Any
from sqlalchemy import select, func  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

from backend.app.models.report import Report, ReportType, ReportFormat, ReportStatus  # type: ignore
from backend.app.models.incident import Incident, AttackTimeline  # type: ignore
from backend.app.models.investigation import Investigation  # type: ignore
from backend.app.models.response import ResponseAction  # type: ignore
from backend.app.models.alert import Alert  # type: ignore
from backend.app.schemas.report import ReportGenerateRequest  # type: ignore
from backend.app.reporting.builders.executive import ExecutiveReportBuilder  # type: ignore
from backend.app.reporting.builders.technical import TechnicalDossierBuilder  # type: ignore
from backend.app.reporting.builders.compliance import ComplianceReportBuilder  # type: ignore
from backend.app.reporting.renderers.html_renderer import HTMLReportRenderer  # type: ignore
from backend.app.reporting.renderers.markdown_renderer import MarkdownReportRenderer  # type: ignore
from backend.app.reporting.renderers.json_renderer import JSONReportRenderer  # type: ignore
from backend.app.reporting.renderers.csv_renderer import CSVReportRenderer  # type: ignore
from backend.app.audit.service import audit_service  # type: ignore


class SecurityReportEngine:
    """Coordinates data extraction, report synthesis, serialization, and database persistence."""

    async def generate_report(
        self,
        request: ReportGenerateRequest,
        db: AsyncSession,
        user_id: Optional[str] = None,
    ) -> Report:
        """Generates, serializes, and persists a security report."""
        incident = None
        investigation = None
        timeline_entries = []
        soar_actions = []
        alerts = []

        # 1. Fetch Incident context if specified
        if request.incident_id:
            stmt = select(Incident).where(Incident.id == request.incident_id)
            res = await db.execute(stmt)
            incident = res.scalar_one_or_none()

            # Timeline
            t_stmt = select(AttackTimeline).where(AttackTimeline.incident_id == request.incident_id)
            t_res = await db.execute(t_stmt)
            timeline_entries = list(t_res.scalars().all())

            # Investigation
            inv_stmt = select(Investigation).where(Investigation.incident_id == request.incident_id)
            inv_res = await db.execute(inv_stmt)
            investigation = inv_res.scalars().first()

            # SOAR Actions
            s_stmt = select(ResponseAction).where(ResponseAction.incident_id == request.incident_id)
            s_res = await db.execute(s_stmt)
            soar_actions = list(s_res.scalars().all())

            # Alerts
            a_stmt = select(Alert).where(Alert.incident_id == request.incident_id)
            a_res = await db.execute(a_stmt)
            alerts = list(a_res.scalars().all())

        # 2. Gather platform-level stats
        total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
        total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
        platform_stats = {
            "total_alerts": total_alerts,
            "total_incidents": total_incidents,
            "monitored_hosts": 18,
            "sensor_health": "OPTIMAL",
        }

        # 3. Dispatch to appropriate builder
        if request.report_type == ReportType.EXECUTIVE_SUMMARY:
            data = ExecutiveReportBuilder.build(
                incident=incident,
                investigation=investigation,
                timeline=timeline_entries,
                soar_actions=soar_actions,
                platform_stats=platform_stats,
                custom_title=request.title,
            )
        elif request.report_type in (ReportType.TECHNICAL_FORENSIC_DOSSIER, ReportType.INCIDENT_POST_MORTEM):
            data = TechnicalDossierBuilder.build(
                incident=incident,
                investigation=investigation,
                timeline=timeline_entries,
                soar_actions=soar_actions,
                alerts=alerts,
                custom_title=request.title,
            )
        elif request.report_type == ReportType.COMPLIANCE_AUDIT:
            data = ComplianceReportBuilder.build(
                incident=incident,
                investigation=investigation,
                timeline=timeline_entries,
                soar_actions=soar_actions,
                custom_title=request.title,
            )
        else:
            data = ExecutiveReportBuilder.build(
                incident=incident,
                investigation=investigation,
                timeline=timeline_entries,
                soar_actions=soar_actions,
                platform_stats=platform_stats,
                custom_title=request.title,
            )

        # 4. Dispatch to requested renderer
        if request.format == ReportFormat.HTML:
            content = HTMLReportRenderer.render(data)
        elif request.format == ReportFormat.MARKDOWN:
            content = MarkdownReportRenderer.render(data)
        elif request.format == ReportFormat.JSON:
            content = JSONReportRenderer.render(data)
        elif request.format == ReportFormat.CSV:
            content = CSVReportRenderer.render(data)
        else:
            content = HTMLReportRenderer.render(data)

        # 5. Persist Report Entity
        report = Report(
            title=data.get("title", request.title or "Security Report"),
            report_type=request.report_type,
            format=request.format,
            status=ReportStatus.COMPLETED,
            incident_id=request.incident_id,
            generated_by_user_id=user_id,
            content=content,
            metadata_json={
                "composite_risk_score": data.get("composite_risk_score", 0.0),
                "timeline_events_count": len(timeline_entries),
                "soar_actions_count": len(soar_actions),
                "format": request.format.value,
            },
            file_size_bytes=len(content.encode("utf-8")),
        )

        db.add(report)
        await db.commit()
        await db.refresh(report)

        # 6. Audit Trail Logging
        await audit_service.log_event(
            db=db,
            action="REPORT_GENERATED",
            resource_type="REPORT",
            resource_id=report.id,
            user_id=user_id,
            details={
                "title": report.title,
                "report_type": report.report_type.value,
                "format": report.format.value,
                "incident_id": report.incident_id,
                "file_size_bytes": report.file_size_bytes,
            },
        )

        return report


# Global reporting engine instance
report_engine = SecurityReportEngine()

