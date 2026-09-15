# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Multi-Agent Investigation Coordinator and Orchestrator."""

import os
import sys
import logging
import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.investigation import Investigation, InvestigationStatus
from backend.app.models.incident import Incident
from backend.app.investigation.agents.triage_agent import TriageAnalystAgent
from backend.app.investigation.agents.evidence_hunter import EvidenceHunterAgent
from backend.app.investigation.agents.forensic_agent import ForensicMitreAgent
from backend.app.investigation.agents.lead_investigator import LeadInvestigatorAgent
from backend.app.api.websockets.manager import ws_manager

logger = logging.getLogger("cyberdefense.investigation.coordinator")


class InvestigationCoordinator:
    """Orchestrates multi-agent investigative workflows, anti-hallucination checks, and persistence."""

    def __init__(self):
        self.triage_agent = TriageAnalystAgent()
        self.evidence_agent = EvidenceHunterAgent()
        self.forensic_agent = ForensicMitreAgent()
        self.lead_agent = LeadInvestigatorAgent()
        self._investigation_times: List[float] = []
        self._fp_count = 0
        self._total_runs = 0

    async def run_investigation(
        self,
        incident_context: Dict[str, Any],
        analyst_id: Optional[str] = None,
        db_session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Runs complete multi-agent investigation pipeline for an incident."""
        start_time = time.monotonic()
        self._total_runs += 1
        incident_id = str(incident_context.get("id") or incident_context.get("incident_id") or "INC-STANDALONE")
        investigation_id = f"inv-{uuid.uuid4().hex[:12]}"

        logger.info("Starting Multi-Agent Investigation [%s] for Incident [%s]", investigation_id, incident_id)

        working_memory: Dict[str, Any] = {
            "evidence": [],
            "hypotheses": [],
            "scratchpads": {},
        }

        try:
            # 1. Tier 1: Triage Assessment
            triage_res = await self.triage_agent.analyze(incident_context, working_memory)
            working_memory["urgency"] = triage_res.get("urgency")
            working_memory["false_positive_probability"] = triage_res.get("false_positive_probability", 0.0)
            working_memory["evidence"].extend(triage_res.get("evidence", []))
            working_memory["hypotheses"].extend(triage_res.get("hypotheses", []))
            working_memory["scratchpads"]["triage"] = triage_res.get("scratchpad", [])

            # 2. Tier 2: Evidence Hunter (CTI, UEBA, Network flows)
            evidence_res = await self.evidence_agent.analyze(incident_context, working_memory)
            working_memory["evidence"].extend(evidence_res.get("evidence", []))
            working_memory["hypotheses"].extend(evidence_res.get("hypotheses", []))
            working_memory["scratchpads"]["evidence_hunter"] = evidence_res.get("scratchpad", [])

            # 3. Tier 3: Forensic Specialist (MITRE ATT&CK, CVE matching)
            forensic_res = await self.forensic_agent.analyze(incident_context, working_memory)
            working_memory["evidence"].extend(forensic_res.get("evidence", []))
            working_memory["hypotheses"].extend(forensic_res.get("hypotheses", []))
            working_memory["scratchpads"]["forensic"] = forensic_res.get("scratchpad", [])

            # 4. Supervisor: Lead AI Investigator (Reconciliation & Segregated Report Generation)
            lead_res = await self.lead_agent.analyze(incident_context, working_memory)
            working_memory["scratchpads"]["lead_investigator"] = lead_res.get("scratchpad", [])

            duration = time.monotonic() - start_time
            self._investigation_times.append(duration)
            if lead_res.get("false_positive_probability", 0.0) >= 0.50:
                self._fp_count += 1

            completed_at = datetime.now(timezone.utc)

            # Persist in Database if session provided
            if db_session:
                try:
                    inv_record = Investigation(
                        id=investigation_id,
                        incident_id=incident_id,
                        analyst_id=analyst_id,
                        status=InvestigationStatus.COMPLETED,
                        observed_evidence=lead_res.get("observed_evidence", {}),
                        inferred_hypotheses=lead_res.get("inferred_hypotheses", {}),
                        agent_scratchpad=working_memory["scratchpads"],
                        executive_summary=lead_res.get("executive_summary"),
                        technical_analysis=lead_res.get("technical_analysis"),
                        completed_at=completed_at,
                    )
                    db_session.add(inv_record)
                    await db_session.commit()
                except Exception as dbe:
                    logger.warning("Could not persist Investigation to DB: %s", str(dbe))

            # Broadcast to SOC Analyst WebSocket clients
            await ws_manager.broadcast({
                "type": "INVESTIGATION_COMPLETED",
                "investigation_id": investigation_id,
                "incident_id": incident_id,
                "urgency": lead_res.get("urgency"),
                "recommended_playbook": lead_res.get("recommended_playbook"),
                "false_positive_probability": lead_res.get("false_positive_probability"),
                "evidence_count": len(lead_res.get("observed_evidence", {}).get("items", [])),
            })

            return {
                "id": investigation_id,
                "incident_id": incident_id,
                "analyst_id": analyst_id,
                "status": "COMPLETED",
                "observed_evidence": lead_res.get("observed_evidence", {}),
                "inferred_hypotheses": lead_res.get("inferred_hypotheses", {}),
                "agent_scratchpad": working_memory["scratchpads"],
                "executive_summary": lead_res.get("executive_summary"),
                "technical_analysis": lead_res.get("technical_analysis"),
                "recommended_playbook": lead_res.get("recommended_playbook"),
                "false_positive_probability": lead_res.get("false_positive_probability", 0.05),
                "duration_seconds": round(duration, 3),
                "created_at": datetime.now(timezone.utc),
                "completed_at": completed_at,
            }

        except Exception as e:
            logger.error("Multi-agent investigation failed for incident %s: %s", incident_id, str(e), exc_info=True)
            return {
                "id": investigation_id,
                "incident_id": incident_id,
                "analyst_id": analyst_id,
                "status": "FAILED",
                "observed_evidence": {},
                "inferred_hypotheses": {},
                "agent_scratchpad": working_memory.get("scratchpads", {}),
                "executive_summary": f"Investigation execution failed: {str(e)}",
                "technical_analysis": None,
                "recommended_playbook": None,
                "false_positive_probability": 0.0,
                "duration_seconds": round(time.monotonic() - start_time, 3),
                "created_at": datetime.now(timezone.utc),
                "completed_at": None,
            }

    def get_stats(self) -> Dict[str, Any]:
        """Calculates multi-agent operational telemetry."""
        avg_dur = sum(self._investigation_times) / len(self._investigation_times) if self._investigation_times else 0.0
        fp_rate = (self._fp_count / self._total_runs) if self._total_runs > 0 else 0.0
        return {
            "total_investigations": self._total_runs,
            "completed_count": len(self._investigation_times),
            "running_count": 0,
            "failed_count": self._total_runs - len(self._investigation_times),
            "avg_duration_seconds": round(avg_dur, 3),
            "false_positive_rate": round(fp_rate, 3),
        }


investigation_coordinator = InvestigationCoordinator()

