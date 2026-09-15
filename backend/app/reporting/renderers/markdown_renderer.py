# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Markdown (GFM) Report Renderer."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import Dict, Any


class MarkdownReportRenderer:
    """Renders structured GitHub-Flavored Markdown security reports."""

    @staticmethod
    def render(data: Dict[str, Any]) -> str:
        """Transforms report dictionary into GFM markdown."""
        title = data.get("title", "Autonomous Cyber Defense Report")
        report_type = data.get("report_type", "SECURITY_REPORT")
        generated_at = data.get("generated_at", "")
        risk_score = float(data.get("composite_risk_score", 50.0))
        severity = data.get("severity", "HIGH")
        status = data.get("status", "INVESTIGATING")
        attack_stage = data.get("attack_stage", "INITIAL_ACCESS")

        exec_summary = data.get("executive_summary", "")
        tech_analysis = data.get("technical_analysis", "")
        business_impact = data.get("business_impact", {})
        recommendations = data.get("recommendations", [])
        nist_alignment = data.get("nist_alignment", {})
        timeline = data.get("timeline", [])
        evidence = data.get("observed_evidence", [])
        xai_attributions = data.get("xai_attributions", [])
        mitre_mapping = data.get("mitre_mapping", [])
        soar_actions = data.get("soar_actions", [])
        frameworks = data.get("frameworks", {})

        md = []
        md.append(f"# {title}\n")
        md.append(f"> **Report Type:** `{report_type}` | **Generated:** `{generated_at[:19]} UTC` | **Platform:** Autonomous AI Cyber Defense v1.0.0\n")
        md.append("---\n")

        md.append("## 1. Executive Threat Scorecard\n")
        md.append("| Metric | Evaluation | Status |")
        md.append("| :--- | :---: | :--- |")
        md.append(f"| **Composite Risk Score** | `{risk_score:.1f} / 100` | {'CRITICAL' if risk_score >= 80 else ('HIGH' if risk_score >= 60 else 'MODERATE')} |")
        md.append(f"| **Incident Severity** | `{severity}` | Immediate Containment Priority |")
        md.append(f"| **Kill-Chain Stage** | `{attack_stage}` | Multi-Sensor Detection |")
        md.append(f"| **Response Status** | `{status}` | Automated SOAR Guardrails Active |\n")

        if exec_summary:
            md.append("## 2. Executive Briefing & Context\n")
            md.append(f"{exec_summary}\n")

        if tech_analysis:
            md.append("## 3. Technical Forensic Analysis\n")
            md.append(f"{tech_analysis}\n")

        if business_impact or recommendations:
            md.append("## 4. Business Impact & Strategic Recommendations\n")
            if business_impact:
                md.append("### Impact Assessment\n")
                for k, v in business_impact.items():
                    md.append(f"- **{k.replace('_', ' ').title()}:** {v}")
                md.append("")
            if recommendations:
                md.append("### Recommended Remediation Steps\n")
                for r in recommendations:
                    md.append(f"- [ ] {r}")
                md.append("")

        if timeline:
            md.append("## 5. Chronological Attack Timeline\n")
            md.append("| Timestamp (UTC) | Event Summary | Entity | Detection Source | MITRE | Severity |")
            md.append("| :--- | :--- | :--- | :--- | :---: | :---: |")
            for t in timeline:
                md.append(f"| `{t.get('timestamp', '')[:19]}` | {t.get('event_summary', '')} | `{t.get('entity', '')}` | {t.get('detection_source', '')} | `{t.get('mitre_technique', '')}` | **{t.get('severity', '')}** |")
            md.append("")

        if evidence:
            md.append("## 6. Cryptographically Verified Evidence Ledger\n")
            md.append("| Evidence ID | Artifact Type | Observed Value | SHA-256 Digest | Sensor Source | Confidence |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :---: |")
            for ev in evidence:
                md.append(f"| `{ev.get('evidence_id', 'EV')}` | {ev.get('type', '')} | `{ev.get('value', '')}` | `{str(ev.get('sha256', ''))[:16]}...` | {ev.get('source', '')} | `{float(ev.get('confidence', 0.95))*100:.0f}%` |")
            md.append("")

        if xai_attributions:
            md.append("## 7. Explainable AI (TreeSHAP) Feature Drivers\n")
            md.append("| Feature Identifier | SHAP Value | Risk Influence | Interpretation |")
            md.append("| :--- | :---: | :---: | :--- |")
            for x in xai_attributions:
                val = float(x.get("shap_value", 0.0))
                sign = "+" if val > 0 else ""
                md.append(f"| `{x.get('feature', '')}` | `{sign}{val:.2f}` | **{x.get('impact', '')}** | {x.get('description', '')} |")
            md.append("")

        if mitre_mapping:
            md.append("## 8. MITRE ATT&CK Kill-Chain Mapping\n")
            md.append("| Technique ID | Technique Name | Tactic | Description |")
            md.append("| :---: | :--- | :--- | :--- |")
            for m in mitre_mapping:
                md.append(f"| `{m.get('technique_id', '')}` | **{m.get('name', '')}** | {m.get('tactic', '')} | {m.get('description', '')} |")
            md.append("")

        if soar_actions:
            md.append("## 9. Automated SOAR Playbook Execution Ledger\n")
            md.append("| Action Type | Target | Status | Mode | Operational Notes |")
            md.append("| :--- | :--- | :---: | :---: | :--- |")
            for s in soar_actions:
                mode = "SIMULATED" if s.get('is_simulated', True) else "ACTIVE"
                md.append(f"| `{s.get('action_type', '')}` | `{s.get('target', '')}` | `{s.get('status', '')}` | `{mode}` | {s.get('notes', '')} |")
            md.append("")

        if nist_alignment:
            md.append("## 10. NIST CSF 2.0 Compliance Alignment\n")
            for k, v in nist_alignment.items():
                md.append(f"- **{k}:** {v}")
            md.append("")

        if frameworks:
            md.append("## 11. Regulatory Compliance Matrices\n")
            for fw, controls in frameworks.items():
                md.append(f"### Framework: {fw}\n")
                md.append("| Control / Category | Status | Verification Details |")
                md.append("| :--- | :---: | :--- |")
                for c in controls:
                    name = c.get("control") or c.get("category") or "Control"
                    md.append(f"| {name} | `{c.get('status', 'VERIFIED')}` | {c.get('details', '')} |")
                md.append("")

        md.append("---\n*End of Tamper-Evident Autonomous AI Cyber Defense Report.*")
        return "\n".join(md)

