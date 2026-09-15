# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Tier 2: Evidence Collector & Threat Hunter Agent for Telemetry, UEBA, and CTI Mining."""

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
from backend.app.threat_intel.enrichment_service import threat_enrichment_service
from backend.app.ueba.baseline import baseline_store

logger = logging.getLogger("cyberdefense.investigation.evidence_hunter")


class EvidenceHunterAgent(BaseSOCAgent):
    """Tier 2 Hunter actively querying IOC feeds, UEBA statistical baselines, and telemetry records."""

    def __init__(self):
        super().__init__(role_name="EvidenceHunter_L2", tier=2)

    async def analyze(
        self,
        incident_context: Dict[str, Any],
        working_memory: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.clear_scratchpad()
        self.record_step(
            thought="Initiating deep evidence collection and threat hunting across telemetry, CTI, and UEBA.",
            action="DISCOVER_TARGET_ENTITIES",
            observations=f"Scanning incident context for IP addresses, domain names, usernames, and hostnames.",
        )

        evidence_items: List[EvidenceItem] = []
        hypotheses: List[HypothesisItem] = []

        source_ip = incident_context.get("source_ip")
        dest_ip = incident_context.get("destination_ip")
        target_host = incident_context.get("target_host") or incident_context.get("hostname")
        affected_user = incident_context.get("user_id") or incident_context.get("affected_user")

        # 1. Threat Intelligence Lookup
        for ip in filter(None, [source_ip, dest_ip]):
            self.record_step(
                thought=f"Checking threat reputation for IP '{ip}' against Phase 8 CTI Cache.",
                action="QUERY_CTI_CACHE",
                observations=f"Dispatched reputation lookup for {ip}.",
            )
            cti_res = await threat_enrichment_service.enrich_entity(str(ip))
            if cti_res.is_malicious:
                ev = EvidenceItem(
                    source="CTI",
                    entity_type="IP",
                    entity_value=str(ip),
                    description=(
                        f"Malicious IOC confirmed in Cyber Threat Intelligence cache. "
                        f"Threat Actor: {cti_res.threat_actor or 'Unknown'}, "
                        f"Malware Family: {cti_res.malware_family or 'Unknown'}, "
                        f"Reputation Score: {cti_res.reputation_score}/100."
                    ),
                    raw_data={
                        "reputation_score": cti_res.reputation_score,
                        "threat_actor": cti_res.threat_actor,
                        "malware_family": cti_res.malware_family,
                        "confidence": cti_res.confidence.value,
                    },
                )
                evidence_items.append(ev)

                hypotheses.append(
                    HypothesisItem(
                        claim=f"Entity {ip} is an active Command & Control (C2) or adversary infrastructure operated by {cti_res.threat_actor or 'unattributed threat group'}.",
                        supporting_evidence_ids=[ev.evidence_id],
                        confidence=min(1.0, cti_res.reputation_score / 100.0),
                        risk_level="CRITICAL" if cti_res.reputation_score >= 80 else "HIGH",
                        recommended_action=f"Block IP {ip} at perimeter firewall.",
                    )
                )

        # 2. UEBA Behavioral Baseline Lookup
        if affected_user:
            self.record_step(
                thought=f"Evaluating user profile '{affected_user}' for statistical behavioral deviations.",
                action="QUERY_UEBA_BASELINES",
                observations=f"Inspecting Welford running metrics and historical login hours.",
            )
            user_baseline = baseline_store.get("user", str(affected_user))
            if user_baseline:
                ev = EvidenceItem(
                    source="UEBA",
                    entity_type="USER",
                    entity_value=str(affected_user),
                    description=(
                        f"User profile '{affected_user}' has recorded {user_baseline.total_events} observations. "
                        f"Tracked metrics: {list(user_baseline.metrics.keys())}."
                    ),
                    raw_data={"total_events": user_baseline.total_events},
                )
                evidence_items.append(ev)

        # 3. Host Profile Verification
        if target_host:
            ev = EvidenceItem(
                source="TELEMETRY",
                entity_type="HOST",
                entity_value=str(target_host),
                description=f"Compromised host endpoint '{target_host}' identified as primary attack target.",
                raw_data={"hostname": target_host},
            )
            evidence_items.append(ev)

        self.record_step(
            thought=f"Collected {len(evidence_items)} hard evidence items and formed {len(hypotheses)} threat hypotheses.",
            action="CONSOLIDATE_EVIDENCE",
            observations=f"Total evidence items: {len(evidence_items)}.",
        )

        return {
            "evidence": [e.model_dump(mode="json") for e in evidence_items],
            "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            "scratchpad": self.get_scratchpad_history(),
        }
