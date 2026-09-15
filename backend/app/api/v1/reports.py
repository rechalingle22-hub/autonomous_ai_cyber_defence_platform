# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Security Reports & Incident Dossiers REST API Router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status  # type: ignore
from sqlalchemy import select, desc  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

from backend.app.database.session import get_db  # type: ignore
from backend.app.models.report import Report, ReportType, ReportFormat  # type: ignore
from backend.app.schemas.report import ReportGenerateRequest, ReportResponse, ReportDetailResponse  # type: ignore
from backend.app.reporting.engine import report_engine  # type: ignore
from backend.app.audit.service import audit_service  # type: ignore

router = APIRouter(prefix="/reports", tags=["Security Reports"])



@router.post(
    "/generate",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate Security Report or Dossier",
)
async def generate_report(
    request: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Generates an automated security report (Executive, Technical, or Compliance) in the requested format."""
    try:
        report = await report_engine.generate_report(
            request=request,
            db=db,
            user_id=None,
        )
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}",
        )


@router.get(
    "",
    response_model=List[ReportResponse],
    summary="List Generated Reports",
)
async def list_reports(
    report_type: Optional[ReportType] = None,
    format: Optional[ReportFormat] = None,
    incident_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Lists generated security reports with optional filtering by type, format, or incident."""
    query = select(Report).order_by(desc(Report.created_at))

    if report_type:
        query = query.where(Report.report_type == report_type)
    if format:
        query = query.where(Report.format == format)
    if incident_id:
        query = query.where(Report.incident_id == incident_id)

    query = query.offset(offset).limit(limit)
    res = await db.execute(query)
    return list(res.scalars().all())


@router.get(
    "/{report_id}",
    response_model=ReportDetailResponse,
    summary="Get Report Details and Content",
)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Retrieves report metadata and complete rendered content."""
    stmt = select(Report).where(Report.id == report_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' was not found",
        )
    return report


@router.get(
    "/{report_id}/download",
    summary="Download Report Artifact File",
)
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Streams the report as an attachment file for direct download in browser or API client."""
    stmt = select(Report).where(Report.id == report_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' was not found",
        )

    ext_map = {
        ReportFormat.HTML: ("html", "text/html"),
        ReportFormat.MARKDOWN: ("md", "text/markdown"),
        ReportFormat.JSON: ("json", "application/json"),
        ReportFormat.CSV: ("csv", "text/csv"),
    }

    ext, media_type = ext_map.get(report.format, ("txt", "text/plain"))
    safe_title = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in report.title).strip("_")
    filename = f"{safe_title}_{report.id[:8]}.{ext}"

    return Response(
        content=report.content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-ID": report.id,
            "X-Report-Type": report.report_type.value,
        },
    )


@router.delete(
    "/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Generated Report",
)
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Deletes an archived security report."""
    stmt = select(Report).where(Report.id == report_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' was not found",
        )

    await db.delete(report)
    await db.commit()

    await audit_service.log_event(
        db=db,
        action="REPORT_DELETED",
        resource_type="REPORT",
        resource_id=report_id,
        details={"title": report.title},
    )

