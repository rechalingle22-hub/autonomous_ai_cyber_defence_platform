# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit test suite for Phase 12 Production Hardening, Orchestration & Configuration."""

import os
import sys
import pytest
import yaml

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


def test_env_example_completeness():
    """Validates that .env.example exists and contains all required configuration parameters."""
    env_path = os.path.join(ROOT_DIR, ".env.example")
    assert os.path.isfile(env_path), ".env.example file must exist at project root"

    with open(env_path, "r", encoding="utf-8") as f:
        content = f.read()

    required_vars = [
        "PROJECT_NAME",
        "ENVIRONMENT",
        "SECRET_KEY",
        "DATABASE_URL",
        "REDIS_URL",
        "REDIS_ENABLED",
        "NEO4J_URI",
        "NEO4J_USER",
        "NEO4J_PASSWORD",
        "NEO4J_ENABLED",
        "SIMULATION_MODE",
        "REQUIRE_HUMAN_APPROVAL_FOR_CONTAINMENT",
        "INITIAL_ADMIN_EMAIL",
        "INITIAL_ADMIN_USERNAME",
        "INITIAL_ADMIN_PASSWORD",
    ]

    for var in required_vars:
        assert f"{var}=" in content, f"Expected variable '{var}' to be declared in .env.example"

    # Default defensive safeguard: SIMULATION_MODE must be enabled by default
    assert "SIMULATION_MODE=True" in content or "SIMULATION_MODE=true" in content.lower()


def test_dockerfile_integrity():
    """Validates Dockerfile multi-stage structure, security hardening, and healthcheck."""
    dockerfile_path = os.path.join(ROOT_DIR, "Dockerfile")
    assert os.path.isfile(dockerfile_path), "Dockerfile must exist at project root"

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify Multi-stage architecture
    assert "AS frontend-builder" in content, "Dockerfile must have a frontend builder stage"
    assert "FROM python:3.13-slim AS production" in content, "Dockerfile must use Python 3.13 slim production stage"

    # Verify OpenMP for ML libraries (XGBoost/PyTorch)
    assert "libgomp1" in content, "Dockerfile must install libgomp1 for OpenMP runtime support"

    # Verify Non-root security
    assert "socuser" in content, "Dockerfile must create and utilize non-root user socuser"
    assert "USER socuser" in content, "Dockerfile must switch to unprivileged USER socuser"

    # Verify Healthcheck & Entrypoint
    assert "HEALTHCHECK" in content, "Dockerfile must define a container HEALTHCHECK"
    assert "uvicorn" in content, "Dockerfile ENTRYPOINT must run uvicorn server"


def test_docker_compose_structure():
    """Validates docker-compose.yml configuration, services, volumes, and networks."""
    compose_path = os.path.join(ROOT_DIR, "docker-compose.yml")
    assert os.path.isfile(compose_path), "docker-compose.yml must exist at project root"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "services" in compose_data, "docker-compose.yml must define services"
    services = compose_data["services"]

    # Verify all 4 primary architectural services
    assert "soc-api" in services, "soc-api service must be defined"
    assert "postgres" in services, "postgres service must be defined"
    assert "redis" in services, "redis service must be defined"
    assert "neo4j" in services, "neo4j service must be defined"

    # Verify persistent volume definitions
    assert "volumes" in compose_data, "docker-compose.yml must define persistent volumes"
    volumes = compose_data["volumes"]
    assert "postgres_data" in volumes
    assert "redis_data" in volumes
    assert "neo4j_data" in volumes

    # Verify isolated network
    assert "networks" in compose_data, "docker-compose.yml must define isolated networks"
    assert "cyber-net" in compose_data["networks"]

    # Verify dependency and healthcheck wiring
    api_deps = services["soc-api"].get("depends_on", {})
    assert "postgres" in api_deps
    assert "redis" in api_deps
    assert "neo4j" in api_deps


def test_launcher_scripts():
    """Validates that production and development launcher scripts exist and are executable."""
    prod_script = os.path.join(ROOT_DIR, "scripts", "run_production.sh")
    dev_script = os.path.join(ROOT_DIR, "scripts", "run_dev.sh")

    assert os.path.isfile(prod_script), "scripts/run_production.sh must exist"
    assert os.path.isfile(dev_script), "scripts/run_dev.sh must exist"

    assert os.access(prod_script, os.X_OK), "scripts/run_production.sh must be executable"
    assert os.access(dev_script, os.X_OK), "scripts/run_dev.sh must be executable"


def test_ci_cd_workflow():
    """Validates GitHub Actions CI/CD configuration integrity."""
    ci_path = os.path.join(ROOT_DIR, ".github", "workflows", "ci.yml")
    assert os.path.isfile(ci_path), ".github/workflows/ci.yml must exist"

    with open(ci_path, "r", encoding="utf-8") as f:
        ci_data = yaml.safe_load(f)

    assert "jobs" in ci_data, "CI workflow must define jobs"
    jobs = ci_data["jobs"]

    assert "quality" in jobs, "CI workflow must include quality/linting job"
    assert "test" in jobs, "CI workflow must include test execution job"
    assert "docker-verify" in jobs, "CI workflow must include docker build verification job"

