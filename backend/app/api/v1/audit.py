# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Audit logs query API router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List, Optional, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.models.audit_log import AuditLog
from backend.app.models.user import UserRole
from backend.app.schemas.audit import AuditLogResponse
from backend.app.auth.rbac import require_role

router = APIRouter(prefix="/audit", tags=["Audit Logging"])


@router.get(
    "/logs",
    response_model=List[AuditLogResponse],
    dependencies=[Depends(require_role([UserRole.ADMIN, UserRole.AUDITOR]))],
)
async def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Retrieves immutable SOC platform audit records. Accessible only to ADMIN or AUDITOR roles."""
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))

    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())
