"""Response action and approval schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict
from backend.app.models.response import ActionType, ActionStatus


class ResponseActionCreate(BaseModel):
    incident_id: str
    action_type: ActionType
    target_entity: str
    is_simulation: bool = True
    rationale: str
    risk_impact_score: float = Field(default=0.0, ge=0.0, le=100.0)


class ApprovalRequest(BaseModel):
    decision: str = Field(..., pattern="^(APPROVED|REJECTED)$")
    comments: Optional[str] = None


class ResponseActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    action_type: ActionType
    target_entity: str
    is_simulation: bool
    status: ActionStatus
    rationale: str
    risk_impact_score: float
    created_at: datetime
    executed_at: Optional[datetime] = None
