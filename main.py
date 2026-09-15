"""Root entrypoint for Autonomous AI Cyber Defense Platform."""

import os
import sys

# Ensure repository root is in python path
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.config.settings import settings
from backend.app.main import app

if __name__ == "__main__":
    import uvicorn
    print(f"Starting {settings.PROJECT_NAME} on http://{settings.HOST}:{settings.PORT}")
    print(f"API Documentation available at http://{settings.HOST}:{settings.PORT}/docs")
    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )

