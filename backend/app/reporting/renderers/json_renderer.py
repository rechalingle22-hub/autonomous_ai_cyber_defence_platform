# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Structured JSON / STIX Interoperability Report Renderer."""

import os
import sys
import json

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import Dict, Any


class JSONReportRenderer:
    """Renders structured, machine-readable JSON reports for SIEM and SOAR interchange."""

    @staticmethod
    def render(data: Dict[str, Any]) -> str:
        """Transforms report dictionary into standardized JSON string."""
        payload = {
            "$schema": "https://cyberdefense.org/schemas/report-v1.json",
            "schema_version": "1.0.0",
            "platform": "Autonomous AI Cyber Defense Platform",
            "export_type": "SECURITY_INCIDENT_DOSSIER",
            "data": data,
        }
        return json.dumps(payload, indent=2, default=str)

