# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Master SOC Command Nexus."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class SubsystemHealthResponse(BaseModel):
    id: str
    name: str
    code: str
    category: str
    engine_type: str
    status: str
    latency_ms: float
    uptime_percent: float
    events_per_sec: int
    endpoint: str


class MasterPostureResponse(BaseModel):
    defense_readiness_index: float
    platform_status: str
    total_subsystems: int
    online_subsystems: int
    mean_time_to_detect_sec: float
    mean_time_to_remediate_sec: float
    automated_containment_rate: float
    total_events_processed: int
    total_threats_blocked: int
    zero_trust_status: str
    choke_points_severed: int
    active_cve_mitigations: int
    cis_cloud_compliance_percent: float
    sbom_components_governed: int
    is_lockdown_active: bool
    lockdown_details: Optional[Dict[str, Any]] = None
    subsystems: List[SubsystemHealthResponse]
    last_evaluated_at: str


class EmergencyLockdownRequest(BaseModel):
    operator: Optional[str] = "SOC_COMMANDER"
    reason: Optional[str] = "COORDINATED_APT_CONTAINMENT"


class EmergencyLockdownResponse(BaseModel):
    status: str
    lockdown_id: str
    is_lockdown_active: bool
    actions_executed_count: int
    quarantined_subnets_count: int
    readiness_index: float
    audit_trail_id: str
    details: Dict[str, Any]
    timestamp: str


class LiftLockdownResponse(BaseModel):
    status: str
    message: str
    lifted_at: str
    previous_lockdown_id: Optional[str] = None


class DiagnosticItemResponse(BaseModel):
    subsystem_id: str
    name: str
    code: str
    health: str
    latency_ms: float
    uptime_percent: float
    memory_leak_check: str
    concurrency_lock_check: str


class DiagnosticsResponse(BaseModel):
    platform_certification: str
    total_checks_passed: int
    total_checks_failed: int
    ai_defense_score: float
    diagnostics_timestamp: str
    engine_results: List[DiagnosticItemResponse]

