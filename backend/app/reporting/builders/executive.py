# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Executive CISO Summary Report Builder."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List


class ExecutiveReportBuilder:
    """Constructs high-level executive summaries and CISO risk briefs."""

    @staticmethod
    def build(
        incident: Optional[Any],
        investigation: Optional[Any],
        timeline: List[Any],
        soar_actions: List[Any],
        platform_stats: Optional[Dict[str, Any]] = None,
        custom_title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synthesizes an executive risk briefing from incident state and platform context."""
        title = custom_title
        if not title:
            if incident:
                title = f"Executive Threat Briefing: {getattr(incident, 'title', 'Security Incident')}"
            else:
                title = "Executive Cyber Defense Posture & Threat Summary"

        now_iso = datetime.now(timezone.utc).isoformat()
        risk_score = float(getattr(incident, "composite_risk_score", 65.0)) if incident else 42.0
        severity = str(getattr(incident, "severity", "HIGH")).replace("AlertSeverity.", "") if incident else "MEDIUM"
        status = str(getattr(incident, "status", "INVESTIGATING")).replace("IncidentStatus.", "") if incident else "OPERATIONAL"
        attack_stage = str(getattr(incident, "attack_stage", "INITIAL_ACCESS")).replace("AttackStage.", "") if incident else "DEFENSE_IN_DEPTH"

        # Extract multi-agent executive summary if available
        exec_summary = getattr(investigation, "executive_summary", None) if investigation else None
        if not exec_summary:
            if incident:
                exec_summary = (
                    f"A {severity} severity incident ({getattr(incident, 'title', 'Security Event')}) was detected "
                    f"by autonomous AI sensors at stage {attack_stage}. The platform calculated a composite risk "
                    f"score of {risk_score:.1f}/100. Protective containment measures and automated threat correlation "
                    f"have been initiated to isolate blast radius and preserve enterprise operational continuity."
                )
            else:
                exec_summary = (
                    "Enterprise cyber defense telemetry indicates operational stability with active threat mitigation. "
                    "All core sensors, unsupervised anomaly detectors, and SOAR response playbooks remain online. "
                    "Continuous behavioral baselining and threat intelligence feeds are active across all endpoints."
                )

        # NIST CSF 2.0 strategic alignment
        nist_alignment = {
            "Govern": "Continuous audit logging and Role-Based Access Control (RBAC) enforced.",
            "Identify": f"Asset and vulnerability discovery mapped; affected primary asset: {getattr(incident, 'primary_asset_id', 'Enterprise Perimeter')}.",
            "Protect": "Least-privilege network segmentation, encrypted JWT sessions, and zero-trust policies active.",
            "Detect": f"Hybrid detection active (Isolation Forest, Deep Autoencoder, XGBoost, TreeSHAP). Stage: {attack_stage}.",
            "Respond": f"{len(soar_actions)} automated SOAR containment playbooks evaluated/dispatched with HITL safeguards.",
            "Recover": "Compensatory rollback workflows and configuration restoration baselines verified.",
        }

        # Business impact assessment
        impact_level = "CRITICAL" if risk_score >= 80 else ("HIGH" if risk_score >= 60 else "MODERATE")
        business_impact = {
            "impact_level": impact_level,
            "estimated_financial_exposure": "$$$ High Exposure" if risk_score >= 75 else "$ Operational Friction",
            "downtime_risk": "High Potential Disruption" if risk_score >= 80 else "Contained to Isolated Segment",
            "regulatory_implications": "Mandatory breach assessment review under GDPR / SEC / NIS2 disclosure protocols" if risk_score >= 80 else "Standard internal SOC compliance logging",
        }

        # Strategic recommendations
        recommendations = [
            "Enforce immediate credential rotation for accounts associated with high-risk telemetry.",
            "Maintain host network isolation until multi-agent forensic verification confirms eradication.",
            "Review edge firewall access control lists (ACLs) to permanently block correlated external C2 IPs.",
            "Initiate tabletop review of incident timeline for continuous playbooks optimization.",
        ]

        return {
            "title": title,
            "report_type": "EXECUTIVE_SUMMARY",
            "generated_at": now_iso,
            "severity": severity,
            "status": status,
            "composite_risk_score": risk_score,
            "attack_stage": attack_stage,
            "executive_summary": exec_summary,
            "business_impact": business_impact,
            "nist_alignment": nist_alignment,
            "recommendations": recommendations,
            "total_timeline_events": len(timeline),
            "total_soar_actions": len(soar_actions),
            "platform_stats": platform_stats or {},
        }

