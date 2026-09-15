"""Autonomous AI Cyber Defense Platform - Application Entrypoint.

Configures FastAPI, lifespan hooks, CORS middleware, API v1 routes,
WebSocket streaming, and database auto-seeding.
"""

import os
import sys

# Ensure repository root and virtual environment site-packages are in python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from backend.app.config.settings import settings
from backend.app.database.session import init_db, AsyncSessionLocal
from backend.app.database.redis_client import redis_manager
from backend.app.database.neo4j_client import neo4j_manager
from backend.app.models.user import User, UserRole
from backend.app.auth.security import get_password_hash
from backend.app.api.v1 import api_v1_router
from backend.app.api.websockets.manager import ws_manager


async def seed_initial_admin() -> None:
    """Seeds default administrator account on first boot if no admin exists."""
    async with AsyncSessionLocal() as session:
        stmt = select(User).where(User.username == settings.INITIAL_ADMIN_USERNAME)
        result = await session.execute(stmt)
        if not result.scalar_one_or_none():
            admin_user = User(
                username=settings.INITIAL_ADMIN_USERNAME,
                email=settings.INITIAL_ADMIN_EMAIL,
                hashed_password=get_password_hash(settings.INITIAL_ADMIN_PASSWORD),
                role=UserRole.ADMIN,
                is_active=True,
            )
            session.add(admin_user)
            await session.commit()


from backend.app.streaming import event_broker, stream_worker


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manages system startup and shutdown lifecycles."""
    # Startup:
    await init_db()
    await seed_initial_admin()
    await redis_manager.connect()
    await neo4j_manager.connect()
    stream_worker.register_handlers()
    await event_broker.start()
    yield
    # Shutdown:
    await event_broker.stop()
    await redis_manager.disconnect()
    await neo4j_manager.disconnect()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description=(
        "Autonomous AI Cyber Defense Platform REST & WebSocket API.\n\n"
        "Provides defensive cybersecurity telemetry ingestion, AI/ML threat detection, "
        "UEBA profiling, alert correlation, attack timeline reconstruction, multi-agent AI SOC, "
        "and safe simulated response orchestration."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from backend.app.api.v1.health import router as health_router
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse

# Mount Root Health Check & REST API v1
app.include_router(health_router)
app.include_router(api_v1_router, prefix=settings.API_V1_STR)

# Mount Embedded SOC Frontend Dashboard & Static Assets
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.mount("/dashboard", StaticFiles(directory=STATIC_DIR, html=True), name="dashboard")

    @app.get("/", include_in_schema=False)
    async def root_dashboard_redirect():
        return RedirectResponse(url="/dashboard/")


# Real-time WebSocket Endpoint
@app.websocket("/ws/soc")
async def soc_websocket_endpoint(websocket: WebSocket) -> None:
    """Real-time bi-directional telemetry and alert stream for SOC analysts."""
    await ws_manager.connect(websocket)
    try:
        # Initial greeting and handshake
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to Autonomous AI Cyber Defense Platform Real-Time Stream",
        })
        while True:
            data = await websocket.receive_text()
            # Echo or process client heartbeats
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )

