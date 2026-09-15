# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Tabular CSV Report Renderer."""

import os
import sys
import csv
import io

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import Dict, Any


class CSVReportRenderer:
    """Renders tabular CSV reports for spreadsheet analysis and regulatory audit ingestion."""

    @staticmethod
    def render(data: Dict[str, Any]) -> str:
        """Transforms report dictionary into standard RFC 4180 CSV."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Write Report Metadata Header
        writer.writerow(["# REPORT_TITLE", data.get("title", "")])
        writer.writerow(["# REPORT_TYPE", data.get("report_type", "")])
        writer.writerow(["# GENERATED_AT_UTC", data.get("generated_at", "")])
        writer.writerow(["# COMPOSITE_RISK_SCORE", f"{float(data.get('composite_risk_score', 0.0)):.1f}"])
        writer.writerow([])

        # Section 1: Timeline Events
        timeline = data.get("timeline", [])
        if timeline:
            writer.writerow(["SECTION", "TIMELINE_EVENTS"])
            writer.writerow(["Timestamp_UTC", "Event_Summary", "Entity", "Detection_Source", "MITRE_Technique", "Severity"])
            for t in timeline:
                writer.writerow([
                    t.get("timestamp", ""),
                    t.get("event_summary", ""),
                    t.get("entity", ""),
                    t.get("detection_source", ""),
                    t.get("mitre_technique", ""),
                    t.get("severity", ""),
                ])
            writer.writerow([])

        # Section 2: Observed Evidence Items
        evidence = data.get("observed_evidence", [])
        if evidence:
            writer.writerow(["SECTION", "OBSERVED_EVIDENCE"])
            writer.writerow(["Evidence_ID", "Artifact_Type", "Observed_Value", "SHA256_Digest", "Sensor_Source", "Confidence"])
            for ev in evidence:
                writer.writerow([
                    ev.get("evidence_id", ""),
                    ev.get("type", ""),
                    ev.get("value", ""),
                    ev.get("sha256", ""),
                    ev.get("source", ""),
                    f"{float(ev.get('confidence', 0.95)):.2f}",
                ])
            writer.writerow([])

        # Section 3: TreeSHAP Feature Attributions
        xai = data.get("xai_attributions", [])
        if xai:
            writer.writerow(["SECTION", "EXPLAINABLE_AI_SHAP"])
            writer.writerow(["Feature", "SHAP_Value", "Impact_Direction", "Interpretation"])
            for x in xai:
                writer.writerow([
                    x.get("feature", ""),
                    f"{float(x.get('shap_value', 0.0)):.4f}",
                    x.get("impact", ""),
                    x.get("description", ""),
                ])
            writer.writerow([])

        # Section 4: SOAR Incident Response Actions
        soar = data.get("soar_actions", [])
        if soar:
            writer.writerow(["SECTION", "SOAR_CONTAINMENT_ACTIONS"])
            writer.writerow(["Action_Type", "Target_Entity", "Execution_Status", "Is_Simulated", "Remediation_Notes"])
            for s in soar:
                writer.writerow([
                    s.get("action_type", ""),
                    s.get("target", ""),
                    s.get("status", ""),
                    s.get("is_simulated", True),
                    s.get("notes", ""),
                ])
            writer.writerow([])

        # Fallback if no specific sub-records: write executive summary key-values
        if not timeline and not evidence and not soar:
            writer.writerow(["Metric_Or_Property", "Value"])
            for k, v in data.items():
                if isinstance(v, (str, int, float, bool)):
                    writer.writerow([k, v])

        return output.getvalue()

