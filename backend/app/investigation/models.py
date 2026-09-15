# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Pydantic schemas and DTOs for Multi-Agent AI SOC Investigation Engine."""

import os
import sys
import uuid
from enum import Enum
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.investigation import InvestigationStatus


class EvidenceItem(BaseModel):
    """Immutable verified fact from telemetry, CTI, UEBA, or alert logs."""
    evidence_id: str = Field(default_factory=lambda: f"ev-{uuid.uuid4().hex[:8]}")
    source: str = Field(..., description="TELEMETRY | CTI | UEBA | ALERT | LOG")
    entity_type: str = Field(..., description="IP | HOST | USER | PROCESS | FILE_HASH")
    entity_value: str
    description: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HypothesisItem(BaseModel):
    """Probabilistic deduction or threat attribution requiring evidence linkage."""
    hypothesis_id: str = Field(default_factory=lambda: f"hyp-{uuid.uuid4().hex[:8]}")
    claim: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    risk_level: str = Field(default="HIGH", description="LOW | MEDIUM | HIGH | CRITICAL")
    recommended_action: Optional[str] = None


class AgentScratchpadEntry(BaseModel):
    """Internal reasoning log for a specific specialized agent."""
    agent_role: str
    thought_process: str
    action_taken: str
    observations: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InvestigationTriggerRequest(BaseModel):
    """API payload to trigger an automated investigation on an incident."""
    incident_id: str
    analyst_id: Optional[str] = None
    priority: str = Field(default="HIGH", description="LOW | MEDIUM | HIGH | CRITICAL")
    notes: Optional[str] = None


class HypothesisAddRequest(BaseModel):
    """API payload to manually add an analyst hypothesis to an ongoing case."""
    claim: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    risk_level: str = Field(default="HIGH")
    recommended_action: Optional[str] = None


class InvestigationResponse(BaseModel):
    """Complete investigation case dossier returned by REST API."""
    id: str
    incident_id: str
    analyst_id: Optional[str] = None
    status: str
    observed_evidence: Dict[str, Any] = Field(default_factory=dict)
    inferred_hypotheses: Dict[str, Any] = Field(default_factory=dict)
    agent_scratchpad: Dict[str, Any] = Field(default_factory=dict)
    executive_summary: Optional[str] = None
    technical_analysis: Optional[str] = None
    recommended_playbook: Optional[str] = None
    false_positive_probability: float = 0.0
    created_at: datetime
    completed_at: Optional[datetime] = None


InvestigationReport = InvestigationResponse


class InvestigationStatsResponse(BaseModel):
    """Operational performance metrics for the multi-agent investigation service."""
    total_investigations: int
    completed_count: int
    running_count: int
    failed_count: int
    avg_duration_seconds: float
    false_positive_rate: float
