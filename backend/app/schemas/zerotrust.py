# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Zero-Trust Adaptive Access Control & Micro-Segmentation."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ContextualAccessEvaluateRequest(BaseModel):
    user_id: str = Field(..., description="Subject user email or account identifier")
    resource_id: str = Field(..., description="Target service, API, or data resource URI")
    resource_sensitivity: str = Field("INTERNAL", description="Resource tier (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED_CROWN_JEWEL)")
    auth_level: str = Field("HARDWARE_MFA_FIDO2", description="Assurance level (PASSWORD_ONLY, PASSWORD_SMS, HARDWARE_MFA_FIDO2)")
    device_posture: Optional[Dict[str, bool]] = Field(default_factory=dict, description="Device security checks (edr_active, disk_encrypted, os_patched, firewall_on)")
    ueba_anomaly_score: float = Field(0.0, description="Behavioral anomaly score (0.0 to 1.0) from UEBA")
    network_context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Network reputation and VPN/Tor flags")
    active_incident_link: bool = Field(False, description="Whether subject is linked to an active attack graph incident")
    source_subnet: Optional[str] = Field(None, description="Source subnet or IP cidr")
    destination_subnet: Optional[str] = Field(None, description="Destination subnet or IP cidr")


class ContextualAccessEvaluateResponse(BaseModel):
    evaluation_id: str
    user_id: str
    resource_id: str
    resource_sensitivity: str
    trust_score: float
    decision: str
    reason: str
    score_breakdown: Dict[str, float]
    evaluated_at: str


class MicrosegmentationPolicyRequest(BaseModel):
    name: str = Field(..., description="Descriptive policy name")
    source_subnet: str = Field(..., description="Source CIDR or subnet (e.g. 10.0.1.0/24)")
    destination_subnet: str = Field(..., description="Destination CIDR or subnet (e.g. 10.0.2.0/24)")
    port_protocol: str = Field("ANY", description="Port and protocol constraint (e.g. 443/TCP)")
    action: str = Field("DENY", description="Enforcement action (ALLOW or DENY)")
    description: Optional[str] = Field("", description="Contextual policy rationale")


class MicrosegmentationPolicyResponse(BaseModel):
    id: str
    name: str
    source_subnet: str
    destination_subnet: str
    port_protocol: str
    action: str
    is_enabled: bool
    description: str
    created_at: Optional[str] = None


class StepUpChallengeResponse(BaseModel):
    challenge_id: str
    session_id: str
    status: str
    required_auth: str
    created_at: str
    expires_at: str


class ZeroTrustMetricsResponse(BaseModel):
    average_trust_score: float
    active_policies_count: int
    total_microsegmentation_policies: int
    continuous_verification_rate_percent: float
    active_sessions_monitored: int
    total_evaluations_completed: int
    blocked_access_attempts: int
    nist_compliance_framework: str
    evaluated_at: str

