# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""API integration tests for Security Reporting endpoints."""

import os
import sys
import uuid
import pytest
from httpx import AsyncClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


@pytest.mark.asyncio
async def test_generate_executive_report_html(async_client: AsyncClient):
    """Verifies generating an executive HTML report."""
    payload = {
        "title": "Quarterly Executive Briefing",
        "report_type": "EXECUTIVE_SUMMARY",
        "format": "HTML",
    }
    resp = await async_client.post("/api/v1/reports/generate", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert data["title"] == "Quarterly Executive Briefing"
    assert data["report_type"] == "EXECUTIVE_SUMMARY"
    assert data["format"] == "HTML"
    assert data["status"] == "COMPLETED"
    assert data["file_size_bytes"] > 0
    assert "id" in data


@pytest.mark.asyncio
async def test_generate_technical_dossier_markdown(async_client: AsyncClient):
    """Verifies generating a technical forensic dossier in Markdown format."""
    payload = {
        "report_type": "TECHNICAL_FORENSIC_DOSSIER",
        "format": "MARKDOWN",
    }
    resp = await async_client.post("/api/v1/reports/generate", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert data["report_type"] == "TECHNICAL_FORENSIC_DOSSIER"
    assert data["format"] == "MARKDOWN"
    assert data["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_list_and_filter_reports(async_client: AsyncClient):
    """Verifies listing reports with optional filtering."""
    # Seed a JSON report
    await async_client.post(
        "/api/v1/reports/generate",
        json={"report_type": "COMPLIANCE_AUDIT", "format": "JSON"},
    )

    resp = await async_client.get("/api/v1/reports?format=JSON")
    assert resp.status_code == 200
    reports = resp.json()
    assert isinstance(reports, list)
    assert len(reports) >= 1
    assert all(r["format"] == "JSON" for r in reports)


@pytest.mark.asyncio
async def test_get_report_details_and_content(async_client: AsyncClient):
    """Verifies fetching detailed report content by ID."""
    gen_resp = await async_client.post(
        "/api/v1/reports/generate",
        json={"title": "Detail Fetch Test", "report_type": "EXECUTIVE_SUMMARY", "format": "HTML"},
    )
    report_id = gen_resp.json()["id"]

    resp = await async_client.get(f"/api/v1/reports/{report_id}")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["id"] == report_id
    assert "content" in detail
    assert "<!DOCTYPE html>" in detail["content"]


@pytest.mark.asyncio
async def test_download_report_attachment(async_client: AsyncClient):
    """Verifies report download endpoint returns correct attachment headers and media type."""
    gen_resp = await async_client.post(
        "/api/v1/reports/generate",
        json={"title": "Download Test Report", "report_type": "TECHNICAL_FORENSIC_DOSSIER", "format": "CSV"},
    )
    report_id = gen_resp.json()["id"]

    resp = await async_client.get(f"/api/v1/reports/{report_id}/download")
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert "text/csv" in resp.headers.get("content-type", "")
    assert len(resp.text) > 0


@pytest.mark.asyncio
async def test_delete_report_endpoint(async_client: AsyncClient):
    """Verifies deleting an archived security report."""
    gen_resp = await async_client.post(
        "/api/v1/reports/generate",
        json={"title": "To Delete", "report_type": "EXECUTIVE_SUMMARY", "format": "JSON"},
    )
    report_id = gen_resp.json()["id"]

    del_resp = await async_client.delete(f"/api/v1/reports/{report_id}")
    assert del_resp.status_code == 204

    # Confirm 404
    get_resp = await async_client.get(f"/api/v1/reports/{report_id}")
    assert get_resp.status_code == 404

