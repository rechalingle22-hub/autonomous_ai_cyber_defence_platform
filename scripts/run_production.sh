#!/usr/bin/env bash
# ==============================================================================
# Autonomous AI Cyber Defense Platform - Production Deployment Launcher
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

echo "======================================================================"
echo "  Autonomous AI Cyber Defense Platform - Production Orchestrator      "
echo "======================================================================"

# 1. Check Docker & Docker Compose availability
if ! command -v docker >/dev/null 2>&1; then
    echo "[-] Error: Docker is not installed or not in PATH." >&2
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "[-] Error: Docker Compose is not available." >&2
    exit 1
fi

# 2. Ensure .env exists
if [ ! -f .env ]; then
    echo "[*] No .env file found. Creating from .env.example..."
    cp .env.example .env
    echo "[!] Default .env created. Review credentials before internet-facing deployment."
fi

# 3. Build and launch multi-container stack
echo "[*] Building and starting containerized services (soc-api, postgres, redis, neo4j)..."
docker compose up --build -d

echo "[*] Waiting for SOC API service to report healthy..."
MAX_ATTEMPTS=30
ATTEMPT=0
HEALTH_URL="http://localhost:8000/api/v1/health"

until curl -s -f "$HEALTH_URL" >/dev/null 2>&1 || [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    echo "    Attempt $ATTEMPT/$MAX_ATTEMPTS: waiting for platform startup..."
    sleep 2
done

if [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; then
    echo "[-] Warning: Healthcheck timed out. Checking container logs:"
    docker compose logs --tail=25 soc-api
    exit 1
fi

echo "======================================================================"
echo "  Platform Successfully Deployed & Operational!                       "
echo "======================================================================"
echo "  * SOC Web Dashboard:       http://localhost:8000/dashboard/        "
echo "  * REST API & OpenAPI Docs: http://localhost:8000/docs              "
echo "  * Health Status Endpoint:  http://localhost:8000/api/v1/health     "
echo "  * Neo4j Graph Browser:     http://localhost:7474                   "
echo "  * Relational Database:     localhost:5432 (cyberdefense)           "
echo "  * Redis Cache/Broker:      localhost:6379                          "
echo "======================================================================"
echo "  To view live logs:    docker compose logs -f soc-api                "
echo "  To shut down stack:   docker compose down                           "
echo "======================================================================"

