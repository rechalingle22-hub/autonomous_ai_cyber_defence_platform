# ==============================================================================
# Stage 1: Frontend Static Bundle Builder
# ==============================================================================
FROM node:24-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# ==============================================================================
# Stage 2: Production Python Runtime Environment
# ==============================================================================
FROM python:3.13-slim AS production

LABEL maintainer="Autonomous AI Cyber Defense Platform Team"
LABEL description="Hardened Multi-Container Autonomous AI SOC Platform"

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install critical system libraries and OpenMP runtime for XGBoost/PyTorch
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Security: Create dedicated unprivileged non-root user
RUN groupadd -g 10001 socgroup && \
    useradd -u 10001 -g socgroup -m -s /bin/bash socuser

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend application code, ML artifacts, and config
COPY backend/ /app/backend/
COPY ml/ /app/ml/
COPY main.py pyproject.toml pyrightconfig.json pytest.ini /app/

# Copy compiled frontend assets from Stage 1 into FastAPI static directory
COPY --from=frontend-builder /app/backend/app/static/ /app/backend/app/static/

# Secure file permissions for non-root runtime
RUN chown -R socuser:socgroup /app

USER socuser

EXPOSE 8000

# Container Healthcheck Probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

