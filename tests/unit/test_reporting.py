# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit test suite for Phase 13 Automated Security Reporting & Incident Dossier Engine."""

import os
import sys
import json
import pytest
from datetime import datetime, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.report import ReportType, ReportFormat, ReportStatus
from backend.app.models.incident import Incident, AttackTimeline, IncidentStatus, AttackStage
from backend.app.models.alert import AlertSeverity
from backend.app.models.investigation import Investigation, InvestigationStatus
from backend.app.models.response import ResponseAction, ActionType, ActionStatus
from backend.app.reporting.builders.executive import ExecutiveReportBuilder
from backend.app.reporting.builders.technical import TechnicalDossierBuilder
from backend.app.reporting.builders.compliance import ComplianceReportBuilder
from backend.app.reporting.renderers.html_renderer import HTMLReportRenderer
from backend.app.reporting.renderers.markdown_renderer import MarkdownReportRenderer
from backend.app.reporting.renderers.json_renderer import JSONReportRenderer
from backend.app.reporting.renderers.csv_renderer import CSVReportRenderer
from backend.app.reporting.engine import SecurityReportEngine
from backend.app.schemas.report import ReportGenerateRequest


class MockIncident:
    id = "INC-TEST-1001"
    title = "Credential Stuffing & Exfiltration Campaign"
    severity = AlertSeverity.HIGH
    composite_risk_score = 84.5
    status = IncidentStatus.INVESTIGATING
    attack_stage = AttackStage.EXFILTRATION
    primary_asset_id = "srv-db-prod-01"


class MockTimelineEntry:
    timestamp = datetime.now(timezone.utc)
    event_summary = "Anomalous SSH outbound burst detected"
    entity = "10.0.1.50"
    detection_source = "Isolation Forest / XGBoost"
    mitre_technique = "T1048"
    severity = AlertSeverity.HIGH


class MockAction:
    action_type = ActionType.BLOCK_IP
    target = "203.0.113.88"
    status = ActionStatus.EXECUTED
    is_simulated = True
    created_at = datetime.now(timezone.utc)
    notes = "Simulated firewall egress block"


def test_executive_report_builder_with_incident():
    """Verifies executive summary builder constructs CISO metrics and NIST CSF alignments."""
    incident = MockIncident()
    timeline = [MockTimelineEntry()]
    actions = [MockAction()]

    data = ExecutiveReportBuilder.build(
        incident=incident,
        investigation=None,
        timeline=timeline,
        soar_actions=actions,
    )

    assert data["report_type"] == "EXECUTIVE_SUMMARY"
    assert "Credential Stuffing" in data["title"]
    assert data["composite_risk_score"] == 84.5
    assert data["business_impact"]["impact_level"] == "CRITICAL"
    assert "NIST_CSF_2.0" not in data  # nist_alignment is a dict
    assert "Govern" in data["nist_alignment"]
    assert len(data["recommendations"]) >= 3


def test_executive_report_builder_platform_wide():
    """Verifies executive report builder gracefully handles platform-wide overview without single incident."""
    data = ExecutiveReportBuilder.build(
        incident=None,
        investigation=None,
        timeline=[],
        soar_actions=[],
        platform_stats={"total_alerts": 42, "total_incidents": 3},
    )

    assert data["report_type"] == "EXECUTIVE_SUMMARY"
    assert "Platform" in data["title"] or "Cyber Defense" in data["title"]
    assert data["composite_risk_score"] > 0
    assert data["platform_stats"]["total_alerts"] == 42


def test_technical_dossier_builder():
    """Verifies technical forensic builder segregates observed evidence and maps TreeSHAP XAI."""
    incident = MockIncident()
    timeline = [MockTimelineEntry()]
    actions = [MockAction()]

    data = TechnicalDossierBuilder.build(
        incident=incident,
        investigation=None,
        timeline=timeline,
        soar_actions=actions,
    )

    assert data["report_type"] == "TECHNICAL_FORENSIC_DOSSIER"
    assert len(data["timeline"]) == 1
    assert data["timeline"][0]["mitre_technique"] == "T1048"
    assert len(data["observed_evidence"]) >= 1
    assert len(data["inferred_hypotheses"]) >= 1
    assert len(data["xai_attributions"]) >= 4
    assert len(data["mitre_mapping"]) >= 2
    assert len(data["soar_actions"]) == 1


def test_compliance_report_builder():
    """Verifies compliance builder maps to NIST CSF 2.0, ISO 27001, and CIS Controls v8."""
    incident = MockIncident()
    data = ComplianceReportBuilder.build(
        incident=incident,
        investigation=None,
        timeline=[],
        soar_actions=[],
    )

    assert data["report_type"] == "COMPLIANCE_AUDIT"
    frameworks = data["frameworks"]
    assert "NIST_CSF_2.0" in frameworks
    assert "ISO_27001_2022" in frameworks
    assert "CIS_CONTROLS_V8" in frameworks
    assert "root_cause_analysis" in data["post_mortem"]


def test_html_renderer():
    """Verifies HTML renderer produces self-contained printable HTML document."""
    data = ExecutiveReportBuilder.build(
        incident=MockIncident(),
        investigation=None,
        timeline=[MockTimelineEntry()],
        soar_actions=[MockAction()],
    )
    html_output = HTMLReportRenderer.render(data)

    assert "<!DOCTYPE html>" in html_output
    assert "<title>" in html_output
    assert "@media print" in html_output
    assert "Credential Stuffing" in html_output
    assert "Composite Risk Score" in html_output


def test_markdown_renderer():
    """Verifies Markdown renderer generates standard GitHub-flavored Markdown."""
    data = TechnicalDossierBuilder.build(
        incident=MockIncident(),
        investigation=None,
        timeline=[MockTimelineEntry()],
        soar_actions=[MockAction()],
    )
    md_output = MarkdownReportRenderer.render(data)

    assert "# Technical Forensic Dossier" in md_output
    assert "## 1. Executive Threat Scorecard" in md_output
    assert "| Timestamp (UTC) | Event Summary |" in md_output
    assert "T1048" in md_output


def test_json_renderer():
    """Verifies JSON renderer emits valid structured schema-compliant JSON."""
    data = TechnicalDossierBuilder.build(
        incident=MockIncident(),
        investigation=None,
        timeline=[MockTimelineEntry()],
        soar_actions=[MockAction()],
    )
    json_output = JSONReportRenderer.render(data)
    parsed = json.loads(json_output)

    assert parsed["schema_version"] == "1.0.0"
    assert "data" in parsed
    assert parsed["data"]["incident_id"] == "INC-TEST-1001"


def test_csv_renderer():
    """Verifies CSV renderer emits standard delimited tabular records."""
    data = TechnicalDossierBuilder.build(
        incident=MockIncident(),
        investigation=None,
        timeline=[MockTimelineEntry()],
        soar_actions=[MockAction()],
    )
    csv_output = CSVReportRenderer.render(data)

    assert "# REPORT_TITLE" in csv_output
    assert "SECTION,TIMELINE_EVENTS" in csv_output
    assert "Anomalous SSH outbound burst detected" in csv_output
