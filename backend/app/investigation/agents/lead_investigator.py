# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Lead AI Investigator (Supervisor) for Anti-Hallucination Evidence Synthesis and Reporting."""

import os
import sys
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.investigation.agents.base import BaseSOCAgent
from backend.app.investigation.models import (
    EvidenceItem,
    HypothesisItem,
    InvestigationReport,
)
from backend.app.response.playbooks import playbook_registry

logger = logging.getLogger("cyberdefense.investigation.lead")


class LeadInvestigatorAgent(BaseSOCAgent):
    """Lead Supervisor Agent reconciling multi-agent findings with strict anti-hallucination guardrails."""

    def __init__(self):
        super().__init__(role_name="LeadInvestigator_Supervisor", tier=4)

    async def analyze(
        self,
        incident_context: Dict[str, Any],
        working_memory: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.clear_scratchpad()
        self.record_step(
            thought="Beginning synthesis of multi-agent investigation findings across Triage, Evidence, and Forensics.",
            action="RECONCILE_FINDINGS",
            observations="Consolidating gathered evidence and probabilistic hypotheses.",
        )

        wm = working_memory or {}
        all_evidence: List[Dict[str, Any]] = wm.get("evidence", [])
        all_hypotheses: List[Dict[str, Any]] = wm.get("hypotheses", [])
        fp_prob = float(wm.get("false_positive_probability", 0.05))
        urgency = wm.get("urgency", "P2_HIGH")

        # 1. Anti-Hallucination Guardrail Check
        # Ensure every hypothesis is grounded in at least one verified evidence ID
        grounded_hypotheses = []
        valid_evidence_ids = {e.get("evidence_id") for e in all_evidence if "evidence_id" in e}

        for hyp in all_hypotheses:
            supporting_ids = hyp.get("supporting_evidence_ids", [])
            # Filter supporting IDs to those genuinely present in observed evidence
            grounded_ids = [eid for eid in supporting_ids if eid in valid_evidence_ids]
            if grounded_ids:
                hyp["supporting_evidence_ids"] = grounded_ids
                grounded_hypotheses.append(hyp)
            else:
                self.record_step(
                    thought="Anti-Hallucination Guardrail Triggered: Ungrounded hypothesis detected and suppressed.",
                    action="SUPPRESS_HALLUCINATION",
                    observations=f"Hypothesis '{hyp.get('claim')}' lacked verified evidence citations.",
                )

        # 2. Select Recommended Response Playbook from Phase 9
        attack_stage = incident_context.get("attack_stage")
        attack_category = incident_context.get("attack_category") or incident_context.get("title")
        matched_playbook = playbook_registry.match_playbook(
            attack_stage=attack_stage,
            attack_category=attack_category,
        )
        rec_playbook_id = matched_playbook.playbook_id if matched_playbook else "PB-RECON-01"

        # 3. Draft CISO Executive Summary
        incident_id = incident_context.get("id", "INC-UNKNOWN")
        incident_title = incident_context.get("title", "Unnamed Threat Incident")
        severity = incident_context.get("severity", "HIGH")
        risk_score = incident_context.get("composite_risk_score", 50.0)

        executive_summary = (
            f"EXECUTIVE SUMMARY: Incident {incident_id} ('{incident_title}') has been investigated by the "
            f"Autonomous AI SOC multi-agent team. Assessed Threat Level: {severity} (Composite Risk Score: {risk_score}/100, "
            f"Triage Priority: {urgency}). False-Positive Probability is evaluated at {fp_prob*100:.1f}%. "
            f"The investigation confirmed {len(all_evidence)} verified indicators of compromise and formed "
            f"{len(grounded_hypotheses)} evidence-grounded hypotheses. Recommended Immediate Action: Deploy SOAR "
            f"Playbook '{rec_playbook_id}' ({matched_playbook.name if matched_playbook else 'General Response'}) "
            f"under simulation or authorized containment mode."
        )

        # 4. Draft Technical Forensic Analysis
        tech_lines = [
            f"### Technical Forensic Dossier for Incident {incident_id}",
            f"- **Attack Stage**: {attack_stage or 'Initial Access / Execution'}",
            f"- **Source Entity**: {incident_context.get('source_ip', 'Internal/Unknown')}",
            f"- **Target Entity**: {incident_context.get('destination_ip') or incident_context.get('target_host', 'Perimeter')}",
            "",
            "#### Observed Hard Evidence (Ground Truth):",
        ]
        for idx, ev in enumerate(all_evidence, 1):
            tech_lines.append(f"{idx}. [{ev.get('source')}] **{ev.get('entity_type')}**: `{ev.get('entity_value')}` — {ev.get('description')}")

        tech_lines.extend(["", "#### Grounded Threat Hypotheses & Inferences:"])
        for idx, hyp in enumerate(grounded_hypotheses, 1):
            cites = ", ".join(hyp.get("supporting_evidence_ids", []))
            tech_lines.append(f"{idx}. **Claim**: {hyp.get('claim')} (Confidence: {float(hyp.get('confidence', 0.8))*100:.0f}%, Risk: {hyp.get('risk_level')}) [Evidence: {cites}]")

        tech_lines.extend([
            "",
            "#### Recommended SOAR Playbook:",
            f"- **Playbook ID**: `{rec_playbook_id}`",
            f"- **Description**: {matched_playbook.description if matched_playbook else 'Perimeter containment'}",
        ])
        technical_analysis = "\n".join(tech_lines)

        self.record_step(
            thought="Investigation synthesis finalized with segregated evidence, grounded hypotheses, and playbook recommendation.",
            action="GENERATE_FINAL_REPORT",
            observations=f"Drafted Executive Summary ({len(executive_summary)} chars) and Technical Report ({len(technical_analysis)} chars).",
        )

        return {
            "executive_summary": executive_summary,
            "technical_analysis": technical_analysis,
            "recommended_playbook": rec_playbook_id,
            "observed_evidence": {"items": all_evidence, "count": len(all_evidence)},
            "inferred_hypotheses": {"items": grounded_hypotheses, "count": len(grounded_hypotheses)},
            "false_positive_probability": fp_prob,
            "urgency": urgency,
            "scratchpad": self.get_scratchpad_history(),
        }

