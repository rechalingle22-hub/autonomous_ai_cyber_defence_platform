# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Health and readiness check endpoints."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path:
        sys.path.insert(0, p)

from typing import Dict, Any

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.config.settings import settings
from backend.app.database.session import get_db
from backend.app.database.redis_client import get_redis
from backend.app.database.neo4j_client import get_neo4j

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", summary="Liveness Probe")
async def liveness() -> Dict[str, Any]:
    """Basic health check to verify ASGI process is alive."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/ready", summary="Readiness Probe")
async def readiness(
    db: AsyncSession = Depends(get_db),
    redis: Any = Depends(get_redis),
    neo4j: Any = Depends(get_neo4j),
) -> Dict[str, Any]:
    """Deep readiness check validating database, cache, and graph engine connectivity."""
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    redis_status = "connected"
    try:
        ping = await redis.ping()
        if not ping:
            redis_status = "unresponsive"
    except Exception as e:
        redis_status = f"unhealthy: {str(e)}"

    neo4j_status = "connected"
    try:
        conn = await neo4j.verify_connectivity() if hasattr(neo4j, "verify_connectivity") else True
        if not conn:
            neo4j_status = "disconnected"
    except Exception as e:
        neo4j_status = f"unhealthy: {str(e)}"

    is_ready = db_status == "connected"
    return {
        "ready": is_ready,
        "components": {
            "database": db_status,
            "cache": redis_status,
            "graph": neo4j_status,
        },
    }

