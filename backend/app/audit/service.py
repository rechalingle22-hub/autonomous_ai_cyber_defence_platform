# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Tamper-evident audit logging service."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import Optional, Dict, Any  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

try:
    from ..models.audit_log import AuditLog  # type: ignore
except (ImportError, ValueError):
    from backend.app.models.audit_log import AuditLog  # type: ignore



class AuditService:
    """Records security-critical actions and access events."""

    @staticmethod
    async def log_event(
        db: AsyncSession,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        """Persists a new immutable audit record to the database."""
        audit_entry = AuditLog(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            details=details or {},
            ip_address=ip_address,
        )
        db.add(audit_entry)
        await db.commit()
        await db.refresh(audit_entry)
        return audit_entry


audit_service = AuditService()

