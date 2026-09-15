# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Autonomous Cloud Security Posture Management (CSPM) & IaC Remediation REST API Router."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.schemas.cspm import (
    CspmPolicyResponse,
    CloudFindingResponse,
    IacPatchResponse,
    RemediationResponse,
    CspmMetricsResponse,
)
from backend.app.cspm.engine import cspm_engine
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/cspm", tags=["Cloud Security Posture Management (CSPM) & IaC Guard"])


@router.get(
    "/metrics",
    response_model=CspmMetricsResponse,
    summary="Get Global Multi-Cloud CSPM & CIS Compliance Metrics",
)
async def get_cspm_metrics() -> Any:
    """Returns CIS compliance scores across AWS, Azure, GCP, K8s, and finding distributions."""
    return cspm_engine.get_metrics()


@router.get(
    "/policies",
    response_model=List[CspmPolicyResponse],
    summary="List Multi-Cloud CIS Benchmark Policies",
)
async def list_policies() -> Any:
    """Retrieves all registered CIS AWS, Azure, GCP, and Kubernetes benchmark policies."""
    return cspm_engine.get_policies()


@router.get(
    "/findings",
    response_model=List[CloudFindingResponse],
    summary="List Cloud Misconfiguration Findings",
)
async def list_findings(
    provider: Optional[str] = Query(None, description="Filter by cloud provider: AWS, AZURE, GCP, KUBERNETES"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by status: OPEN, REMEDIATED, SUPPRESSED"),
) -> Any:
    """Retrieves multi-cloud security findings with optional provider and severity filters."""
    return cspm_engine.get_findings(provider=provider, severity=severity, status=status)


@router.get(
    "/findings/{finding_id}",
    response_model=CloudFindingResponse,
    summary="Get Single Cloud Security Finding",
)
async def get_finding(finding_id: str) -> Any:
    """Retrieves finding details and detected resource ARN."""
    try:
        return cspm_engine.get_finding(finding_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@router.get(
    "/findings/{finding_id}/patch",
    response_model=IacPatchResponse,
    summary="Get Synthesized Infrastructure-as-Code (IaC) Patch",
)
async def get_finding_patch(finding_id: str) -> Any:
    """Returns AI-synthesized unified diff (Terraform HCL or Kubernetes YAML) for a finding."""
    try:
        return cspm_engine.get_finding_patch(finding_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@router.post(
    "/findings/{finding_id}/remediate",
    response_model=RemediationResponse,
    summary="Trigger Autonomous IaC Remediation & Generate Git Pull Request",
)
async def remediate_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Applies verified IaC patch to codebase, closes finding, and generates verified Git PR."""
    try:
        result = cspm_engine.remediate_finding(finding_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="CSPM_IAC_REMEDIATED",
        resource_type="CSPM_FINDING",
        resource_id=finding_id,
        details={
            "finding_id": finding_id,
            "pull_request_id": result["pull_request_id"],
            "pull_request_branch": result["pull_request_branch"],
            "target_file": result["target_file"],
            "new_compliance_score": result["new_compliance_score"],
        },
    )

    return result


@router.post(
    "/reset",
    summary="Reset CSPM Findings to Baseline",
)
async def reset_cspm_findings() -> Any:
    """Resets all cloud findings back to baseline OPEN state."""
    cspm_engine.reset_findings()
    return {"message": "CSPM findings reset to baseline", "status": "RESET_SUCCESS"}

