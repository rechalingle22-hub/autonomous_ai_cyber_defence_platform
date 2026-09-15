# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Cyber Deception, Honeytokens & Decoy Network."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class HoneytokenDeployRequest(BaseModel):
    token_type: str = Field(..., description="Honeytoken type (API_KEY, DATABASE_CREDENTIAL, AWS_SECRET_KEY, JWT_TOKEN, CANARY_FILE, SSH_KEY)")
    name: str = Field(..., description="Human-readable descriptive name for the decoy credential")
    bait_path: Optional[str] = Field(None, description="Filesystem or configuration target path where token is planted")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom context and bait metadata")


class HoneytokenResponse(BaseModel):
    id: str
    name: str
    token_type: str
    token_value: Optional[str] = None
    masked_value: str
    bait_path: str
    status: str
    hit_count: int
    created_at: str
    last_tripped_at: Optional[str] = None
    last_attacker_ip: Optional[str] = None
    last_user_agent: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HoneytokenTripwireRequest(BaseModel):
    token_value_or_id: str = Field(..., description="The honeytoken value or identifier being accessed")
    source_ip: str = Field("192.168.1.185", description="Source IP address attempting the unauthorized access")
    user_agent: str = Field("python-requests/2.31.0 (Adversary Recon Scanner)", description="Adversary client user agent")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Audit and request context")


class HoneytokenTripwireResponse(BaseModel):
    tripwire_triggered: bool
    token: Optional[Dict[str, Any]] = None
    alert: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class DecoyInteractRequest(BaseModel):
    command_or_payload: str = Field(..., description="Command string or payload sent to the decoy service")
    source_ip: str = Field("192.168.1.185", description="Attacker IP address")


class DecoyServiceResponse(BaseModel):
    id: str
    service_type: str
    name: str
    port: int
    protocol: str
    fake_banner: str
    status: str
    interaction_count: int
    captured_payloads: List[Dict[str, Any]] = Field(default_factory=list)


class DeceptionMetricsResponse(BaseModel):
    total_honeytokens_deployed: int
    active_honeytokens: int
    tripped_honeytokens: int
    total_honeytoken_hits: int
    total_decoys_online: int
    engaged_decoys: int
    total_decoy_interactions: int
    true_positive_fidelity_percent: float
    zero_false_positives_guaranteed: bool
    recent_tripwires: List[Dict[str, Any]] = Field(default_factory=list)
    evaluated_at: str

