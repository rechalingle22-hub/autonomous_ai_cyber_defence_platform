# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Multi-Agent AI SOC Investigation and Threat Hunting Engine."""

from backend.app.investigation.models import (
    EvidenceItem,
    HypothesisItem,
    AgentScratchpadEntry,
    InvestigationTriggerRequest,
    HypothesisAddRequest,
    InvestigationResponse,
    InvestigationStatsResponse,
)
from backend.app.investigation.agents import (
    BaseSOCAgent,
    TriageAnalystAgent,
    EvidenceHunterAgent,
    ForensicMitreAgent,
    LeadInvestigatorAgent,
)
from backend.app.investigation.coordinator import (
    InvestigationCoordinator,
    investigation_coordinator,
)

__all__ = [
    "EvidenceItem",
    "HypothesisItem",
    "AgentScratchpadEntry",
    "InvestigationTriggerRequest",
    "HypothesisAddRequest",
    "InvestigationResponse",
    "InvestigationStatsResponse",
    "BaseSOCAgent",
    "TriageAnalystAgent",
    "EvidenceHunterAgent",
    "ForensicMitreAgent",
    "LeadInvestigatorAgent",
    "InvestigationCoordinator",
    "investigation_coordinator",
]

