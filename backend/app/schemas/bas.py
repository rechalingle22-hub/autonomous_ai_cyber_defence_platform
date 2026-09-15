# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Breach and Attack Simulation (BAS) Engine."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class KillChainStageDetail(BaseModel):
    stage_id: str
    stage_order: int
    stage_name: str
    tactic: str
    technique_id: str
    technique_name: str
    execution_payload: str
    default_detecting_layer: str
    mitigation: str
    severity: str
    simulated_latency_ms: int
    default_outcome: str


class CampaignProfileResponse(BaseModel):
    campaign_id: str
    name: str
    actor_alias: str
    actor_origin: str
    target_sectors: List[str]
    description: str
    complexity: str
    estimated_duration_sec: float
    stages: List[KillChainStageDetail]


class CampaignExecutionRequest(BaseModel):
    campaign_id: str = Field("APT29", description="Adversary campaign identifier (e.g. APT29, FIN7, LAZARUS, BLACKCAT)")
    target_environment: Optional[str] = Field("Simulated Multi-VPC Cloud & On-Premises Range", description="Target test environment name")
    dry_run: bool = Field(False, description="Dry-run mode without persisting run record")


class StageResultResponse(BaseModel):
    stage_id: str
    stage_name: str
    tactic: str
    technique_id: str
    technique_name: str
    status: str
    detecting_layer: str
    mitigation: str
    execution_time_ms: int
    severity: str
    payload_sample: Optional[str] = None


class CampaignExecutionResponse(BaseModel):
    simulation_id: str
    campaign_id: str
    campaign_name: str
    target_environment: str
    started_at: str
    completed_at: str
    duration_seconds: float
    total_stages: int
    prevented_stages: int
    detected_stages: int
    evaded_stages: int
    prevention_rate_percent: float
    detection_rate_percent: float
    posture_score: float
    mean_time_to_block_ms: float
    summary_verdict: str
    stage_results: List[StageResultResponse]
    dry_run: bool = False


class CoverageMatrixItemResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    status: str
    detecting_layer: str
    campaigns_tested: List[str]
    last_tested_at: str


class BasMetricsResponse(BaseModel):
    overall_posture_score: float
    total_campaigns_available: int
    total_simulations_executed: int
    detection_rate_percent: float
    prevention_rate_percent: float
    mean_time_to_block_ms: float
    mitre_techniques_covered: int
    unmitigated_gaps_count: int
    last_simulation_timestamp: str

