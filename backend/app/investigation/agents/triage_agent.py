# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Tier 1: Triage Analyst Agent for False-Positive Analysis and Incident Urgency Assessment."""

import os
import sys
import logging
from typing import Dict, Any, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.investigation.agents.base import BaseSOCAgent
from backend.app.investigation.models import EvidenceItem, HypothesisItem

logger = logging.getLogger("cyberdefense.investigation.triage")


class TriageAnalystAgent(BaseSOCAgent):
    """Tier 1 Analyst performing initial triage, noise filtration, and false-positive evaluation."""

    def __init__(self):
        super().__init__(role_name="TriageAnalyst_L1", tier=1)

    async def analyze(
        self,
        incident_context: Dict[str, Any],
        working_memory: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.clear_scratchpad()
        self.record_step(
            thought="Beginning initial triage assessment on security incident.",
            action="INGEST_INCIDENT_CONTEXT",
            observations=f"Evaluating incident {incident_context.get('id', 'N/A')}: title='{incident_context.get('title')}', severity='{incident_context.get('severity')}'.",
        )

        risk_score = float(incident_context.get("composite_risk_score", 50.0))
        alerts_count = len(incident_context.get("alerts", []))
        attack_category = str(incident_context.get("attack_category") or incident_context.get("title") or "").upper()
        source_ip = str(incident_context.get("source_ip", "")).strip()

        # Evaluate False-Positive Indicators
        fp_score = 0.05  # Base false positive probability
        fp_reasons = []

        # 1. Single alert with low risk score
        if alerts_count <= 1 and risk_score < 40.0:
            fp_score += 0.35
            fp_reasons.append("Single isolated alert with low risk score (< 40.0).")

        # 2. Source is internal loopback/private RFC1918 without lateral movement indicators
        if source_ip in ["127.0.0.1", "::1", "localhost"]:
            fp_score += 0.40
            fp_reasons.append("Originates from loopback address.")

        # 3. Known maintenance or benign category
        if "BACKUP" in attack_category or "BENIGN" in attack_category:
            fp_score += 0.50
            fp_reasons.append("Category indicates scheduled operational activity.")

        # Suppressing FP if multiple high-confidence indicators exist
        if risk_score >= 75.0 or "RANSOMWARE" in attack_category or "EXFILTRATION" in attack_category:
            fp_score = max(0.01, fp_score - 0.40)

        fp_probability = round(min(0.99, max(0.01, fp_score)), 3)

        # Urgency assignment
        if risk_score >= 80.0 or fp_probability < 0.10:
            urgency = "P1_CRITICAL"
        elif risk_score >= 60.0:
            urgency = "P2_HIGH"
        elif risk_score >= 35.0:
            urgency = "P3_MEDIUM"
        else:
            urgency = "P4_LOW"

        self.record_step(
            thought=f"Calculated false positive probability: {fp_probability}. Assigned triage urgency: {urgency}.",
            action="CALCULATE_TRIAGE_METRICS",
            observations=f"FP score={fp_probability} (drivers: {'; '.join(fp_reasons) if fp_reasons else 'None, multiple strong threat signals'}).",
        )

        evidence_items = [
            EvidenceItem(
                source="ALERT",
                entity_type="INCIDENT_RECORD",
                entity_value=str(incident_context.get("id", "INC-001")),
                description=f"Incident '{incident_context.get('title')}' evaluated with composite risk score {risk_score}.",
                raw_data={"risk_score": risk_score, "alerts_count": alerts_count, "urgency": urgency},
            )
        ]

        hypotheses = []
        if fp_probability >= 0.60:
            hypotheses.append(
                HypothesisItem(
                    claim=f"Incident {incident_context.get('id')} has high probability ({fp_probability*100:.1f}%) of being a false positive or maintenance artifact.",
                    supporting_evidence_ids=[evidence_items[0].evidence_id],
                    confidence=fp_probability,
                    risk_level="LOW",
                    recommended_action="Validate with asset owner before initiating destructive containment.",
                )
            )
        else:
            hypotheses.append(
                HypothesisItem(
                    claim=f"Confirmed actionable security incident requiring escalation (Urgency: {urgency}, True Positive Confidence: {(1.0 - fp_probability)*100:.1f}%).",
                    supporting_evidence_ids=[evidence_items[0].evidence_id],
                    confidence=round(1.0 - fp_probability, 3),
                    risk_level=incident_context.get("severity", "HIGH"),
                    recommended_action="Dispatch Tier 2 Evidence Hunter for CTI and UEBA historical correlation.",
                )
            )

        return {
            "urgency": urgency,
            "false_positive_probability": fp_probability,
            "evidence": [e.model_dump(mode="json") for e in evidence_items],
            "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            "scratchpad": self.get_scratchpad_history(),
        }

