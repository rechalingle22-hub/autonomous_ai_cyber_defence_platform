# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for Autonomous Cloud Security Posture Management (CSPM) & IaC Guard."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class CspmPolicyResponse(BaseModel):
    policy_id: str
    title: str
    provider: str
    benchmark: str
    section: str
    severity: str
    description: str
    remediation_guide: str


class CloudFindingResponse(BaseModel):
    finding_id: str
    policy_id: str
    title: str
    provider: str
    severity: str
    status: str
    resource_id: str
    resource_name: str
    region: str
    first_detected_at: str
    description: str
    iac_file_path: str
    iac_format: str
    remediated_at: Optional[str] = None
    pull_request_id: Optional[str] = None


class IacPatchResponse(BaseModel):
    finding_id: str
    iac_format: str
    target_file: str
    pull_request_branch: str
    commit_message: str
    unified_diff: str
    synthesized_code: str


class RemediationResponse(BaseModel):
    finding_id: str
    title: str
    status: str
    pull_request_id: str
    pull_request_branch: str
    target_file: str
    iac_format: str
    commit_message: str
    applied_at: str
    new_compliance_score: float


class CspmMetricsResponse(BaseModel):
    overall_cis_compliance_percent: float
    total_cloud_resources_scanned: int
    total_findings_count: int
    active_findings_count: int
    remediated_findings_count: int
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    compliance_by_provider: Dict[str, float]
    automated_remediation_rate_percent: float
    last_scan_timestamp: str

