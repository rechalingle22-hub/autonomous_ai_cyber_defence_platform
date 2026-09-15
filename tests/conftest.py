"""Pytest test configuration and async fixtures."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Force in-memory SQLite database for test runs
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ENVIRONMENT"] = "test"
os.environ["SECRET_KEY"] = "TEST_SECRET_KEY_CYBER_DEFENSE_987654321"

from backend.app.main import app
from backend.app.database.session import Base, get_db
from backend.app.models.user import User, UserRole
from backend.app.auth.security import get_password_hash, create_access_token

test_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    echo=False,
    future=True,
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_test_db():
    """Initializes a fresh schema in memory before each test and seeds roles."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed admin and analyst users
    async with TestingSessionLocal() as session:
        admin = User(
            username="test_admin",
            email="admin@test.org",
            hashed_password=get_password_hash("AdminPass123!"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        analyst = User(
            username="test_analyst",
            email="analyst@test.org",
            hashed_password=get_password_hash("AnalystPass123!"),
            role=UserRole.ANALYST,
            is_active=True,
        )
        session.add_all([admin, analyst])
        await session.commit()

    yield

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def override_get_db():
    """Overrides real get_db with test database session."""
    async with TestingSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


app.dependency_overrides[get_db] = override_get_db


@pytest_asyncio.fixture
async def async_client():
    """Async HTTP test client bound to ASGI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def admin_token() -> str:
    """Generates an authorization Bearer token for test_admin."""
    return create_access_token({"sub": "test_admin", "role": "ADMIN"})


@pytest.fixture
def analyst_token() -> str:
    """Generates an authorization Bearer token for test_analyst."""
    return create_access_token({"sub": "test_analyst", "role": "ANALYST"})
