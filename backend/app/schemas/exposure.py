# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Cyber Threat Exposure & Attack Path Validation (APV) Engine."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class CrownJewelResponse(BaseModel):
    id: str
    name: str
    asset_tier: str
    category: str
    criticality_score: float
    ip_address: str
    hostname: str
    data_classification: str
    inbound_paths_count: int
    is_isolated: bool
    compensating_controls: List[str]


class AttackPathNode(BaseModel):
    step_order: int
    node_type: str
    asset_id: str
    asset_name: str
    technique_id: str
    technique_name: str
    cve_id: Optional[str] = None
    description: str
    risk_contribution: float


class AttackPathResponse(BaseModel):
    path_id: str
    title: str
    entry_point: str
    target_crown_jewel_id: str
    target_crown_jewel_name: str
    accumulated_risk_score: float
    hop_count: int
    status: str
    associated_choke_point_ids: List[str]
    nodes: List[AttackPathNode]
    severed_by_choke_point: Optional[str] = None
    severed_at: Optional[str] = None


class ChokePointResponse(BaseModel):
    choke_point_id: str
    title: str
    category: str
    description: str
    affected_paths_count: int
    affected_path_ids: List[str]
    target_assets: List[str]
    remediation_action: str
    disruption_efficiency_percent: float
    is_remediated: bool
    remediated_at: Optional[str] = None


class ChokePointRemediationRequest(BaseModel):
    choke_point_id: str = Field(..., description="Choke point identifier to remediate (e.g. CP-01)")


class ChokePointRemediationResponse(BaseModel):
    choke_point_id: str
    title: str
    severed_paths_count: int
    severed_path_ids: List[str]
    new_resilience_index: float
    remediation_status: str
    applied_at: str


class ExposureMetricsResponse(BaseModel):
    attack_path_resilience_index: float
    total_crown_jewels: int
    isolated_crown_jewels_count: int
    total_attack_paths_discovered: int
    active_attack_paths_count: int
    severed_attack_paths_count: int
    total_choke_points_identified: int
    active_choke_points_count: int
    remediated_choke_points_count: int
    mean_attack_path_length_hops: float
    last_evaluated_at: str

