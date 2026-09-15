# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Threat Hunting & Autonomous Detection-as-Code Engine."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class HuntHypothesisResponse(BaseModel):
    id: str
    title: str
    tactic: str
    mitre_technique: str
    severity: str
    description: str
    data_sources: List[str]
    target_telemetry: str
    query_logic: str
    base_confidence: float


class HuntExecutionRequest(BaseModel):
    hypothesis_id: str = Field(..., description="Target hunting hypothesis identifier (e.g. HYP-001)")
    time_window_hours: int = Field(24, description="Lookback window in hours across telemetry")


class HuntExecutionResponse(BaseModel):
    execution_id: str
    hypothesis_id: str
    hypothesis_title: str
    tactic: str
    mitre_technique: str
    time_window_hours: int
    findings_count: int
    confidence_score: float
    confidence_level: str
    matched_iocs: List[str]
    affected_hosts: List[str]
    query_executed: str
    recommended_action: str
    executed_at: str


class DetectionRuleResponse(BaseModel):
    id: str
    title: str
    format: str
    status: str
    severity: str
    mitre_technique: str
    author: str
    content: str
    hypothesis_id: Optional[str] = None
    created_at: str
    deployed_at: Optional[str] = None


class RuleGenerateRequest(BaseModel):
    hypothesis_id: str = Field(..., description="Hypothesis from which to synthesize detection code")
    rule_format: str = Field("SIGMA_YAML", description="Rule format: SIGMA_YAML or YARA")
    title: Optional[str] = Field(None, description="Custom detection rule title")
    severity: str = Field("high", description="Rule severity: low, medium, high, critical")


class RuleDeployRequest(BaseModel):
    rule_id: str = Field(..., description="Detection rule ID to activate")


class ThreatHuntingMetricsResponse(BaseModel):
    total_hypotheses: int
    total_hunts_executed: int
    hypothesis_validation_rate: float
    total_detection_rules: int
    deployed_active_rules: int
    sigma_rules_count: int
    yara_rules_count: int
    mean_hunt_dwell_reduction_percent: float
    last_hunt_timestamp: str

