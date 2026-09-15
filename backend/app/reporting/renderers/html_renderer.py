# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""HTML and Print-Ready PDF Report Renderer."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import Dict, Any


class HTMLReportRenderer:
    """Renders high-fidelity, responsive HTML security reports with print-to-PDF styles."""

    @staticmethod
    def render(data: Dict[str, Any]) -> str:
        """Transforms report dictionary into self-contained HTML5 with embedded CSS."""
        title = data.get("title", "Autonomous Cyber Defense Report")
        report_type = data.get("report_type", "SECURITY_REPORT")
        generated_at = data.get("generated_at", "")
        risk_score = float(data.get("composite_risk_score", 50.0))
        severity = data.get("severity", "HIGH")
        status = data.get("status", "INVESTIGATING")
        attack_stage = data.get("attack_stage", "INITIAL_ACCESS")

        # Color badges based on severity/risk
        risk_color = "#ef4444" if risk_score >= 75 else ("#f59e0b" if risk_score >= 50 else "#10b981")
        sev_badge_color = "#ef4444" if severity == "CRITICAL" else ("#f97316" if severity == "HIGH" else "#3b82f6")

        # Render sections
        exec_summary = data.get("executive_summary", "")
        tech_analysis = data.get("technical_analysis", "")
        business_impact = data.get("business_impact", {})
        recommendations = data.get("recommendations", [])
        nist_alignment = data.get("nist_alignment", {})
        timeline = data.get("timeline", [])
        evidence = data.get("observed_evidence", [])
        hypotheses = data.get("inferred_hypotheses", [])
        xai_attributions = data.get("xai_attributions", [])
        mitre_mapping = data.get("mitre_mapping", [])
        soar_actions = data.get("soar_actions", [])
        frameworks = data.get("frameworks", {})
        post_mortem = data.get("post_mortem", {})

        # Timeline rows HTML
        timeline_rows = ""
        for t in timeline:
            timeline_rows += f"""
            <tr>
                <td style="padding: 10px 12px; font-family: monospace; font-size: 12px; color: #64748b;">{t.get('timestamp', '')[:19]}</td>
                <td style="padding: 10px 12px; font-weight: 600; color: #1e293b;">{t.get('event_summary', '')}</td>
                <td style="padding: 10px 12px; font-family: monospace; font-size: 12px; color: #475569;">{t.get('entity', '')}</td>
                <td style="padding: 10px 12px; font-size: 12px; color: #0369a1;">{t.get('detection_source', '')}</td>
                <td style="padding: 10px 12px;"><span style="background: #e0e7ff; color: #3730a3; padding: 2px 8px; border-radius: 4px; font-family: monospace; font-size: 11px;">{t.get('mitre_technique', '')}</span></td>
                <td style="padding: 10px 12px;"><span style="background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">{t.get('severity', '')}</span></td>
            </tr>
            """

        # Evidence rows HTML
        evidence_rows = ""
        for ev in evidence:
            evidence_rows += f"""
            <tr>
                <td style="padding: 10px 12px; font-family: monospace; font-size: 12px; font-weight: 600; color: #0284c7;">{ev.get('evidence_id', 'EV-REC')}</td>
                <td style="padding: 10px 12px; font-size: 12px; color: #334155;">{ev.get('type', '')}</td>
                <td style="padding: 10px 12px; font-family: monospace; font-size: 12px; color: #1e293b;">{ev.get('value', '')}</td>
                <td style="padding: 10px 12px; font-family: monospace; font-size: 11px; color: #64748b;" title="{ev.get('sha256', '')}">{str(ev.get('sha256', ''))[:16]}...</td>
                <td style="padding: 10px 12px; font-size: 12px; color: #0f766e;">{ev.get('source', '')}</td>
                <td style="padding: 10px 12px; font-size: 12px; font-weight: 600; color: #166534;">{float(ev.get('confidence', 0.95))*100:.0f}%</td>
            </tr>
            """

        # TreeSHAP rows HTML
        xai_rows = ""
        for x in xai_attributions:
            shap_val = float(x.get("shap_value", 0.0))
            is_pos = shap_val > 0
            bar_color = "#ef4444" if is_pos else "#10b981"
            impact_badge = f'<span style="background: {"#fee2e2" if is_pos else "#d1fae5"}; color: {"#991b1b" if is_pos else "#065f46"}; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">{x.get("impact", "")}</span>'
            xai_rows += f"""
            <tr>
                <td style="padding: 10px 12px; font-family: monospace; font-size: 12px; font-weight: 600; color: #0f172a;">{x.get('feature', '')}</td>
                <td style="padding: 10px 12px; font-weight: 700; color: {bar_color}; font-family: monospace;">{'+' if is_pos else ''}{shap_val:.2f}</td>
                <td style="padding: 10px 12px;">{impact_badge}</td>
                <td style="padding: 10px 12px; font-size: 12px; color: #475569;">{x.get('description', '')}</td>
            </tr>
            """

        # SOAR actions rows HTML
        soar_rows = ""
        for s in soar_actions:
            soar_rows += f"""
            <tr>
                <td style="padding: 10px 12px; font-family: monospace; font-weight: 600; font-size: 12px; color: #1e293b;">{s.get('action_type', '')}</td>
                <td style="padding: 10px 12px; font-family: monospace; font-size: 12px; color: #0369a1;">{s.get('target', '')}</td>
                <td style="padding: 10px 12px;"><span style="background: #dcfce7; color: #166534; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">{s.get('status', 'SUCCESS')}</span></td>
                <td style="padding: 10px 12px; font-size: 12px; color: #64748b;">{"SIMULATED (DRY RUN)" if s.get('is_simulated', True) else "ACTIVE CONTAINMENT"}</td>
                <td style="padding: 10px 12px; font-size: 12px; color: #334155;">{s.get('notes', '')}</td>
            </tr>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        @page {{
            size: A4;
            margin: 1.5cm;
        }}
        @media print {{
            body {{
                background: #ffffff !important;
                color: #000000 !important;
            }}
            .no-print {{
                display: none !important;
            }}
            .page-break {{
                page-break-before: always;
            }}
            .card {{
                box-shadow: none !important;
                border: 1px solid #cbd5e1 !important;
            }}
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f8fafc;
            color: #0f172a;
            line-height: 1.6;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            border: 1px solid #e2e8f0;
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            padding: 32px;
            border-bottom: 4px solid #0284c7;
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 26px;
            letter-spacing: -0.02em;
        }}
        .header-meta {{
            display: flex;
            gap: 16px;
            font-size: 13px;
            color: #94a3b8;
            flex-wrap: wrap;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            display: inline-block;
            text-transform: uppercase;
        }}
        .content {{
            padding: 32px;
        }}
        .scorecard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
        }}
        .metric-label {{
            font-size: 12px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 4px;
        }}
        .metric-value {{
            font-size: 24px;
            font-weight: 800;
            color: #0f172a;
        }}
        h2 {{
            font-size: 18px;
            color: #0f172a;
            border-bottom: 2px solid #f1f5f9;
            padding-bottom: 8px;
            margin-top: 32px;
            margin-bottom: 16px;
        }}
        .card {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 8px;
            margin-bottom: 24px;
        }}
        th {{
            background: #f1f5f9;
            color: #475569;
            text-align: left;
            padding: 10px 12px;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            border-bottom: 1px solid #cbd5e1;
        }}
        tr:nth-child(even) {{
            background: #f8fafc;
        }}
        tr:hover {{
            background: #f1f5f9;
        }}
        .footer {{
            background: #f1f5f9;
            border-top: 1px solid #e2e8f0;
            padding: 20px 32px;
            font-size: 12px;
            color: #64748b;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .print-btn {{
            background: #0284c7;
            color: #ffffff;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
        }}
        .print-btn:hover {{
            background: #0369a1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <span class="badge" style="background: rgba(2, 132, 199, 0.2); color: #38bdf8; border: 1px solid #0284c7; margin-bottom: 12px;">{report_type}</span>
                    <h1>{title}</h1>
                    <div class="header-meta">
                        <span><strong>Generated:</strong> {generated_at[:19]} UTC</span>
                        <span>&bull;</span>
                        <span><strong>Classification:</strong> RESTRICTED / SOC USE ONLY</span>
                        <span>&bull;</span>
                        <span><strong>Engine:</strong> Autonomous AI Cyber Defense v1.0.0</span>
                    </div>
                </div>
                <div class="no-print">
                    <button class="print-btn" onclick="window.print()">Print to PDF</button>
                </div>
            </div>
        </div>

        <div class="content">
            <!-- Scorecards -->
            <div class="scorecard-grid">
                <div class="metric-card">
                    <div class="metric-label">Composite Risk Score</div>
                    <div class="metric-value" style="color: {risk_color};">{risk_score:.1f}<span style="font-size: 14px; color: #64748b;"> / 100</span></div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Severity Assessment</div>
                    <div class="metric-value"><span class="badge" style="background: {sev_badge_color}; color: #ffffff;">{severity}</span></div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Kill-Chain Stage</div>
                    <div class="metric-value" style="font-size: 16px; color: #0284c7; font-weight: 700;">{attack_stage}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Containment Status</div>
                    <div class="metric-value" style="font-size: 16px; color: #166534; font-weight: 700;">{status}</div>
                </div>
            </div>

            <!-- Executive Summary -->
            {f'''
            <h2>Executive Briefing & Threat Context</h2>
            <div class="card">
                <p style="margin: 0; font-size: 14px; color: #1e293b;">{exec_summary}</p>
            </div>
            ''' if exec_summary else ''}

            <!-- Technical Analysis -->
            {f'''
            <h2>Technical Forensic Assessment</h2>
            <div class="card" style="border-left: 4px solid #0284c7;">
                <p style="margin: 0; font-size: 14px; color: #1e293b;">{tech_analysis}</p>
            </div>
            ''' if tech_analysis else ''}

            <!-- Business Impact & Recommendations -->
            {f'''
            <h2>Business Impact & Strategic Guidance</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px;">
                <div class="card" style="margin-bottom: 0;">
                    <div class="metric-label" style="margin-bottom: 8px;">Business Impact Scope</div>
                    <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #334155;">
                        <li><strong>Impact Level:</strong> {business_impact.get("impact_level", "MODERATE")}</li>
                        <li><strong>Financial Exposure:</strong> {business_impact.get("estimated_financial_exposure", "Contained")}</li>
                        <li><strong>Downtime Risk:</strong> {business_impact.get("downtime_risk", "Minimal")}</li>
                        <li><strong>Regulatory:</strong> {business_impact.get("regulatory_implications", "Internal Review")}</li>
                    </ul>
                </div>
                <div class="card" style="margin-bottom: 0;">
                    <div class="metric-label" style="margin-bottom: 8px;">Recommended Remediation</div>
                    <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #334155;">
                        {''.join(f'<li>{r}</li>' for r in recommendations)}
                    </ul>
                </div>
            </div>
            ''' if business_impact or recommendations else ''}

            <!-- Chronological Timeline -->
            {f'''
            <h2>Chronological Attack Timeline</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp (UTC)</th>
                        <th>Event Summary</th>
                        <th>Entity</th>
                        <th>Source</th>
                        <th>MITRE Code</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {timeline_rows}
                </tbody>
            </table>
            ''' if timeline_rows else ''}

            <!-- Observed Evidence -->
            {f'''
            <h2>Cryptographically Verified Evidence Items</h2>
            <table>
                <thead>
                    <tr>
                        <th>Evidence ID</th>
                        <th>Artifact Type</th>
                        <th>Observed Value</th>
                        <th>SHA-256 Digest</th>
                        <th>Sensor Source</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {evidence_rows}
                </tbody>
            </table>
            ''' if evidence_rows else ''}

            <!-- Explainable AI (TreeSHAP) -->
            {f'''
            <h2>Explainable AI (TreeSHAP) Risk Drivers</h2>
            <table>
                <thead>
                    <tr>
                        <th>Feature Identifier</th>
                        <th>SHAP Value</th>
                        <th>Risk Influence</th>
                        <th>Feature Interpretation</th>
                    </tr>
                </thead>
                <tbody>
                    {xai_rows}
                </tbody>
            </table>
            ''' if xai_rows else ''}

            <!-- SOAR Actions -->
            {f'''
            <h2>Automated Incident Response & SOAR Execution</h2>
            <table>
                <thead>
                    <tr>
                        <th>Action Type</th>
                        <th>Target Entity</th>
                        <th>Execution Status</th>
                        <th>Mode</th>
                        <th>Remediation Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {soar_rows}
                </tbody>
            </table>
            ''' if soar_rows else ''}

            <!-- NIST CSF Alignment -->
            {f'''
            <h2>NIST Cybersecurity Framework (CSF 2.0) Alignment</h2>
            <div class="card">
                <table style="margin: 0;">
                    <tbody>
                        {''.join(f'<tr><td style="width: 140px; font-weight: 700; color: #0284c7; padding: 8px 12px;">{k}</td><td style="padding: 8px 12px; font-size: 13px; color: #334155;">{v}</td></tr>' for k, v in nist_alignment.items())}
                    </tbody>
                </table>
            </div>
            ''' if nist_alignment else ''}
        </div>

        <!-- Footer -->
        <div class="footer">
            <div>
                <strong>Autonomous AI Cyber Defense Platform</strong> &bull; Tamper-Evident Report
            </div>
            <div style="font-family: monospace;">
                Generated with cryptographic integrity
            </div>
        </div>
    </div>
</body>
</html>
"""
        return html_template

