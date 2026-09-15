# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Database connection and async session management for SQLAlchemy 2.0.

Supports SQLite async for zero-dependency local testing/development and
PostgreSQL (asyncpg) for production.
"""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import AsyncGenerator  # type: ignore
from sqlalchemy.ext.asyncio import (  # type: ignore
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase  # type: ignore

try:
    from ..config.settings import settings  # type: ignore
except (ImportError, ValueError):
    from backend.app.config.settings import settings  # type: ignore



class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


# Build async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DB_ECHO,
    future=True,
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection yield for FastAPI request lifecycle."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Creates all registered database tables in the configured database."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

