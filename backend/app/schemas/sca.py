# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Software Supply Chain Security (SCA) & Autonomous SBOM Governance."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class SbomSummaryResponse(BaseModel):
    sbom_id: str
    name: str
    version: str
    ecosystem: str
    format: str
    total_components: int
    direct_count: int
    transitive_count: int
    critical_vulns: int
    high_vulns: int
    compliance_status: str
    created_at: str
    serial_number: str


class PackageComponentResponse(BaseModel):
    component_id: str
    sbom_id: str
    name: str
    version: str
    ecosystem: str
    purl: str
    is_direct: bool
    license: str
    license_risk: str
    vulnerabilities_count: int
    has_cisa_kev: bool
    top_cvss: float


class VulnerabilityResponse(BaseModel):
    vuln_id: str
    cve_id: str
    component_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    ecosystem: str
    severity: str
    cvss_score: float
    epss_score: float
    cisa_kev: bool
    cisa_due_date: Optional[str] = None
    title: str
    description: str
    reachability: str
    reachability_rationale: str
    status: str
    detected_at: str
    remediated_at: Optional[str] = None
    remediation_pr: Optional[str] = None


class SupplyChainThreatResponse(BaseModel):
    threat_id: str
    type: str
    package_name: str
    target_package: str
    levenshtein_distance: int
    ecosystem: str
    severity: str
    risk_score: int
    detected_in: str
    detection_reason: str
    status: str
    detected_at: str


class LicenseRiskResponse(BaseModel):
    risk_id: str
    component_id: str
    package_name: str
    version: str
    license: str
    risk_level: str
    category: str
    commercial_impact: str
    recommendation: str
    status: str


class ScaRemediationPatchResponse(BaseModel):
    vuln_id: str
    cve_id: str
    package_name: str
    manifest_file: str
    git_branch: str
    pr_title: str
    commit_message: str
    unified_diff: str


class ScaRemediationRequest(BaseModel):
    vuln_id: str


class ScaRemediationResultResponse(BaseModel):
    status: str
    vuln_id: str
    cve_id: Optional[str] = None
    component_id: Optional[str] = None
    package_name: Optional[str] = None
    new_version: Optional[str] = None
    git_pr_branch: Optional[str] = None
    vulnerability_status: str
    new_health_score: float
    audit_trail_id: str
    timestamp: str


class ScaMetricsResponse(BaseModel):
    health_score: float
    total_sboms: int
    total_components: int
    direct_components: int
    transitive_components: int
    total_vulnerabilities: int
    open_vulnerabilities: int
    remediated_vulnerabilities: int
    remediation_rate: float
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    cisa_kev_active: int
    direct_reachable_active: int
    active_threats_count: int
    license_violations_count: int
    last_scan_time: str

