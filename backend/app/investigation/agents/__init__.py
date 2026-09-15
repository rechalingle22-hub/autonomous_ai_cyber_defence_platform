# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Specialized AI SOC Investigation Agents."""

from backend.app.investigation.agents.base import BaseSOCAgent
from backend.app.investigation.agents.triage_agent import TriageAnalystAgent
from backend.app.investigation.agents.evidence_hunter import EvidenceHunterAgent
from backend.app.investigation.agents.forensic_agent import ForensicMitreAgent
from backend.app.investigation.agents.lead_investigator import LeadInvestigatorAgent

__all__ = [
    "BaseSOCAgent",
    "TriageAnalystAgent",
    "EvidenceHunterAgent",
    "ForensicMitreAgent",
    "LeadInvestigatorAgent",
]

