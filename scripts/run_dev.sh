#!/usr/bin/env bash
# ==============================================================================
# Autonomous AI Cyber Defense Platform - Local Development Runner
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

echo "======================================================================"
echo "  Autonomous AI Cyber Defense Platform - Local Development Mode       "
echo "======================================================================"

# 1. Verify or bootstrap virtual environment
VENV_DIR="$ROOT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    echo "[*] Installing dependencies..."
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install -r requirements.txt
fi

PYTHON_EXEC="$VENV_DIR/bin/python"

# 2. Check if frontend static bundle exists; compile if missing
if [ ! -f "$ROOT_DIR/backend/app/static/index.html" ]; then
    if command -v npm >/dev/null 2>&1 && [ -d "$ROOT_DIR/frontend" ]; then
        echo "[*] Building React SOC Frontend Dashboard..."
        (cd "$ROOT_DIR/frontend" && npm install && npm run build)
    else
        echo "[!] Note: Frontend build not found and npm not detected. Using API fallback."
    fi
fi

# 3. Create development .env if not present
if [ ! -f "$ROOT_DIR/.env" ]; then
    echo "[*] Initializing local development environment configuration..."
    cat <<EOF > "$ROOT_DIR/.env"
PROJECT_NAME="Autonomous AI Cyber Defense Platform (Dev)"
ENVIRONMENT="development"
DEBUG=True
HOST="0.0.0.0"
PORT=8000
DATABASE_URL="sqlite+aiosqlite:///./cyberdefense.db"
SIMULATION_MODE=True
REQUIRE_HUMAN_APPROVAL_FOR_CONTAINMENT=True
REDIS_ENABLED=False
NEO4J_ENABLED=False
KAFKA_ENABLED=False
EOF
fi

# 4. Start the platform with auto-reload
echo "[*] Starting FastAPI platform engine via Uvicorn..."
exec "$PYTHON_EXEC" -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

