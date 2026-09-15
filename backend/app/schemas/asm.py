# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Attack Surface Management & Risk-Based Vulnerability Prioritization."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class DiscoveredAssetResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    criticality: str
    exposure: str
    environment: str
    open_ports: List[int]
    services: List[str]
    active_vulnerabilities_count: int
    has_zero_trust_control: bool
    owner_team: str
    discovered_at: str


class AssetScanRequest(BaseModel):
    subnet_range: str = Field("10.0.0.0/16", description="Target CIDR range or perimeter domain")
    scan_intensity: str = Field("COMPREHENSIVE", description="Discovery mode: PASSIVE, STANDARD, COMPREHENSIVE")


class AssetScanResponse(BaseModel):
    scan_id: str
    subnet_range: str
    scan_intensity: str
    assets_discovered: int
    total_assets: int
    completed_at: str


class PrioritizedVulnerabilityResponse(BaseModel):
    cve_id: str
    title: str
    cvss_score: float
    epss_probability: float
    contextual_risk_score: float
    priority: str
    has_known_exploit: bool
    cisa_kev: bool
    asset_id: str
    asset_hostname: str
    affected_service: str
    status: str
    sla_hours: int
    sla_description: str
    sla_deadline: Optional[str] = None
    sla_breached: bool = False
    score_breakdown: Optional[Dict[str, float]] = None
    resolution_notes: Optional[str] = None
    remediated_at: Optional[str] = None
    discovered_at: str


class VulnerabilityPrioritizeRequest(BaseModel):
    recalculate: bool = Field(True, description="Force re-scoring across all active vulnerabilities")


class VulnerabilityRemediateRequest(BaseModel):
    resolution_notes: str = Field(
        "Automated SOAR virtual patch applied", description="Remediation or mitigation notes"
    )
    action: str = Field(
        "APPLY_VIRTUAL_PATCH", description="Action taken: APPLY_VIRTUAL_PATCH, ISOLATE_HOST, HOST_UPGRADE, ACCEPT_RISK"
    )


class AsmMetricsResponse(BaseModel):
    attack_surface_exposure_score: float
    total_assets: int
    internet_facing_assets: int
    internal_assets: int
    total_vulnerabilities: int
    active_vulnerabilities: int
    remediated_vulnerabilities: int
    p0_critical_count: int
    p1_high_count: int
    avg_epss_probability: float
    sla_compliance_rate: float
    last_scan_timestamp: str

