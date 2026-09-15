# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Autonomous AI Cyber Defense Platform - Configuration & Settings.

Uses Pydantic Settings (v2) for environment variable parsing, typing, and validation.
"""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List  # type: ignore
from pydantic import Field  # type: ignore
from pydantic_settings import BaseSettings, SettingsConfigDict  # type: ignore



class Settings(BaseSettings):
    """Platform configuration loaded from environment variables or defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Project Information
    PROJECT_NAME: str = "Autonomous AI Cyber Defense Platform"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security & JWT Authentication
    SECRET_KEY: str = Field(
        default="SUPER_SECURE_DEV_SECRET_KEY_CHANGE_IN_PRODUCTION_09f26eec8d01d",
        description="Cryptographic secret key for signing JWT tokens",
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS Allowed Origins
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Database Configuration
    # Defaults to SQLite async for self-contained, zero-dependency testing;
    # Can be overridden with postgresql+asyncpg://user:pass@localhost:5432/cyberdefense
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./cyberdefense.db",
        description="SQLAlchemy async connection string",
    )
    DB_ECHO: bool = False

    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_ENABLED: bool = False  # Set to True when Redis is running, fallback to memory if False

    # Neo4j Graph Database
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "cyberdefense_password"
    NEO4J_ENABLED: bool = False  # Set to True when Neo4j is running, fallback to mock if False

    # Apache Kafka Streaming
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_ENABLED: bool = False

    # SOC Simulation & Lab Controls
    SIMULATION_MODE: bool = True
    REQUIRE_HUMAN_APPROVAL_FOR_CONTAINMENT: bool = True

    # Initial Admin Seed
    INITIAL_ADMIN_EMAIL: str = "admin@cyberdefense.org"
    INITIAL_ADMIN_USERNAME: str = "admin"
    INITIAL_ADMIN_PASSWORD: str = "AdminSecOps2026!"


settings = Settings()
