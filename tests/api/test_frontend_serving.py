# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API Integration tests for Embedded Frontend Dashboard Serving."""

import os
import sys
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


@pytest.mark.asyncio
async def test_dashboard_serving_endpoint(async_client: AsyncClient):
    """Verifies that FastAPI serves the compiled SOC Dashboard HTML at /dashboard/."""
    resp = await async_client.get("/dashboard/")
    assert resp.status_code == 200
    text = resp.text
    assert "Autonomous AI Cyber Defense Platform" in text
    assert "SOC Command Center" in text
    assert '<div id="root"></div>' in text


@pytest.mark.asyncio
async def test_root_redirects_to_dashboard(async_client: AsyncClient):
    """Verifies that visiting root / redirects to the dashboard."""
    resp = await async_client.get("/", follow_redirects=False)
    assert resp.status_code in [301, 302, 307, 308]
    assert "/dashboard/" in resp.headers.get("location", "")


@pytest.mark.asyncio
async def test_static_assets_serving(async_client: AsyncClient):
    """Verifies that static assets (CSS/JS) in /static/ are served."""
    static_dir = os.path.join(ROOT_DIR, "backend/app/static/assets")
    if os.path.exists(static_dir):
        files = os.listdir(static_dir)
        css_file = next((f for f in files if f.endswith(".css")), None)
        if css_file:
            resp = await async_client.get(f"/static/assets/{css_file}")
            assert resp.status_code == 200
            assert len(resp.content) > 0

