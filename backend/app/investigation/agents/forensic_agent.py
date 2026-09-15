# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Tier 3: Forensic & ATT&CK Specialist Agent for MITRE Kill-Chain and Vulnerability Analysis."""

import os
import sys
import logging
from typing import Dict, Any, Optional, List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.investigation.agents.base import BaseSOCAgent
from backend.app.investigation.models import EvidenceItem, HypothesisItem
from backend.app.threat_intel.cve_matcher import cve_matcher
from backend.app.threat_intel.mitre_mapper import mitre_mapper

logger = logging.getLogger("cyberdefense.investigation.forensic")


class ForensicMitreAgent(BaseSOCAgent):
    """Tier 3 Forensic Specialist analyzing kill-chain progression, CVE exploitation, and MITRE TTPs."""

    def __init__(self):
        super().__init__(role_name="ForensicAnalyst_L3", tier=3)

    async def analyze(
        self,
        incident_context: Dict[str, Any],
        working_memory: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.clear_scratchpad()
        self.record_step(
            thought="Beginning forensic analysis on MITRE kill-chain progression and service vulnerabilities.",
            action="INSPECT_KILL_CHAIN",
            observations=f"Incident stage: {incident_context.get('attack_stage', 'UNKNOWN')}, category: {incident_context.get('attack_category')}.",
        )

        evidence_items: List[EvidenceItem] = []
        hypotheses: List[HypothesisItem] = []

        attack_stage = str(incident_context.get("attack_stage", "INITIAL_ACCESS")).upper()
        dest_port = incident_context.get("destination_port")
        attack_cat = incident_context.get("attack_category") or incident_context.get("title")

        # 1. Match known CVE exploitation signatures
        if dest_port is not None:
            try:
                port_int = int(dest_port)
                cves = cve_matcher.match_by_port(port_int)
                if cves:
                    cve_desc = ", ".join([f"{c.cve_id} ({c.affected_service})" for c in cves])
                    ev = EvidenceItem(
                        source="CTI",
                        entity_type="PORT_VULNERABILITY",
                        entity_value=str(port_int),
                        description=f"Destination port {port_int} exposed to high-severity vulnerabilities: {cve_desc}.",
                        raw_data={
                            "port": port_int,
                            "cves": [c.model_dump(mode="json") if hasattr(c, "model_dump") else str(c) for c in cves],
                        },
                    )
                    evidence_items.append(ev)

                    first_cve = cves[0]
                    hypotheses.append(
                        HypothesisItem(
                            claim=f"Adversary is potentially exploiting vulnerability on port {port_int} (Likely: {first_cve.cve_id} / {first_cve.affected_service}).",
                            supporting_evidence_ids=[ev.evidence_id],
                            confidence=0.85,
                            risk_level="HIGH",
                            recommended_action=f"Patch and restrict ingress traffic on port {port_int}.",
                        )
                    )
            except (ValueError, TypeError, AttributeError) as err:
                logger.debug("Port CVE lookup skipped: %s", str(err))

        # 2. MITRE ATT&CK Attribution
        ttp_mapping = {
            "RECONNAISSANCE": ("T1046", "Network Service Discovery"),
            "INITIAL_ACCESS": ("T1190", "Exploit Public-Facing Application"),
            "EXECUTION": ("T1059", "Command and Scripting Interpreter"),
            "PERSISTENCE": ("T1053", "Scheduled Task/Job"),
            "PRIVILEGE_ESCALATION": ("T1068", "Exploitation for Privilege Escalation"),
            "LATERAL_MOVEMENT": ("T1550.002", "Pass the Hash / Lateral Pivot"),
            "COLLECTION": ("T1005", "Data from Local System"),
            "EXFILTRATION": ("T1048", "Exfiltration Over Alternative Protocol"),
            "IMPACT": ("T1486", "Data Encrypted for Impact / Ransomware"),
        }

        technique_id, technique_name = ttp_mapping.get(attack_stage, ("T1071", "Standard Application Layer Protocol"))
        ev_mitre = EvidenceItem(
            source="ALERT",
            entity_type="MITRE_TTP",
            entity_value=technique_id,
            description=f"Behavioral pattern attributed to MITRE ATT&CK Technique {technique_id}: '{technique_name}' at stage {attack_stage}.",
            raw_data={"stage": attack_stage, "technique_id": technique_id, "technique_name": technique_name},
        )
        evidence_items.append(ev_mitre)

        # 3. Lateral Movement Risk Assessment
        if attack_stage in ["LATERAL_MOVEMENT", "EXFILTRATION", "IMPACT"]:
            hypotheses.append(
                HypothesisItem(
                    claim=f"Attack has progressed past perimeter breach into advanced stage '{attack_stage}'. Active lateral spread or exfiltration underway.",
                    supporting_evidence_ids=[ev_mitre.evidence_id],
                    confidence=0.90,
                    risk_level="CRITICAL",
                    recommended_action="Execute immediate network isolation on affected endpoints.",
                )
            )

        self.record_step(
            thought=f"Forensic evaluation identified MITRE technique {technique_id} ({technique_name}) and {len(evidence_items)} evidence records.",
            action="FINALIZE_FORENSICS",
            observations=f"Mapped stage={attack_stage}, CVEs found={len(evidence_items) > 1}.",
        )

        return {
            "evidence": [e.model_dump(mode="json") for e in evidence_items],
            "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            "scratchpad": self.get_scratchpad_history(),
        }
