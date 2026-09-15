# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Pydantic schemas and DTOs for SOAR automated response actions and playbooks."""

import os
import sys
from enum import Enum
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.response import ActionType, ActionStatus


class ActionResult(BaseModel):
    """Result of an executed or simulated response action."""
    action_type: ActionType
    target_entity: str
    is_simulation: bool
    status: ActionStatus
    success: bool
    detail: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PlaybookStep(BaseModel):
    """Single action step in a SOAR playbook."""
    step_id: str
    name: str
    action_type: ActionType
    target_field: str = Field(..., description="Field in incident context (e.g. source_ip, hostname, user_id)")
    risk_impact_score: float = Field(default=20.0, ge=0.0, le=100.0)
    requires_approval: bool = Field(default=False)
    rollback_on_failure: bool = Field(default=True)


class PlaybookDefinition(BaseModel):
    """Declarative SOAR Playbook specification."""
    playbook_id: str
    name: str
    description: str
    trigger_criteria: Dict[str, Any] = Field(default_factory=dict, description="Incident criteria matching this playbook")
    steps: List[PlaybookStep] = Field(default_factory=list)
    enabled: bool = Field(default=True)


class PlaybookExecutionResult(BaseModel):
    """Output summary of an executed playbook workflow."""
    playbook_id: str
    incident_id: str
    success: bool
    steps_executed: int
    steps_failed: int
    step_results: List[ActionResult] = Field(default_factory=list)
    pending_approvals_count: int = Field(default=0)
    started_at: datetime
    completed_at: datetime


# API Request / Response schemas
class ActionCreateRequest(BaseModel):
    """Payload to create a manual response action."""
    incident_id: str
    action_type: ActionType
    target_entity: str
    rationale: str
    is_simulation: bool = True
    risk_impact_score: float = Field(default=25.0, ge=0.0, le=100.0)


class ActionApprovalRequest(BaseModel):
    """Payload to approve or reject a pending response action."""
    decision: Optional[str] = Field(default="APPROVED", description="'APPROVED' or 'REJECTED'")
    comments: Optional[str] = Field(default=None)


class ActionResponse(BaseModel):
    """Response DTO for a response action."""
    id: str
    incident_id: str
    action_type: str
    target_entity: str
    is_simulation: bool
    status: str
    rationale: str
    risk_impact_score: float
    created_at: datetime
    executed_at: Optional[datetime] = None


class TriggerPlaybookRequest(BaseModel):
    """Payload to manually trigger a playbook on an incident."""
    playbook_id: str
    incident_id: str
    is_simulation: bool = True


class SOARStatsResponse(BaseModel):
    """Operational telemetry for the SOAR engine."""
    total_actions: int
    pending_approval_count: int
    executed_count: int
    rejected_count: int
    failed_count: int
    active_playbooks_count: int
    simulation_mode_enabled: bool
    hitl_required: bool
