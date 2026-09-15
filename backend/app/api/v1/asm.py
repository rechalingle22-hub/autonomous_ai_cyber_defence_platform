# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Attack Surface Management (ASM) & Risk-Based Vulnerability Prioritization REST API Router."""

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
from backend.app.schemas.asm import (
    DiscoveredAssetResponse,
    AssetScanRequest,
    AssetScanResponse,
    PrioritizedVulnerabilityResponse,
    VulnerabilityPrioritizeRequest,
    VulnerabilityRemediateRequest,
    AsmMetricsResponse,
)
from backend.app.asm.engine import (
    asm_engine,
    ExposureLevel,
    VulnerabilityPriority,
    VulnerabilityStatus,
)
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/asm", tags=["Attack Surface Management (ASM) & RBVM"])


@router.get(
    "/metrics",
    response_model=AsmMetricsResponse,
    summary="Get Global Attack Surface Exposure & RBVM Metrics",
)
async def get_asm_metrics() -> Any:
    """Returns total assets, internet-facing assets, composite exposure score, and vulnerability counts."""
    return asm_engine.get_asm_metrics()


@router.get(
    "/assets",
    response_model=List[DiscoveredAssetResponse],
    summary="List Discovered Threat Surface Assets",
)
async def list_assets(
    exposure: Optional[str] = Query(None, description="Filter by exposure level: INTERNET_FACING, DMZ, INTERNAL_SEGMENTED, AIR_GAPPED"),
) -> Any:
    """Retrieves enterprise assets inventory discovered through automated surface mapping."""
    if exposure and exposure not in [e.value for e in ExposureLevel]:
        valid_exp = [e.value for e in ExposureLevel]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid exposure filter '{exposure}'. Valid options: {valid_exp}",
        )
    return asm_engine.get_assets(filter_exposure=exposure)


@router.post(
    "/assets/scan",
    response_model=AssetScanResponse,
    summary="Trigger Continuous Threat Surface Discovery Scan",
)
async def trigger_scan(
    request: AssetScanRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Initiates an active or passive threat surface probe against corporate subnets or external domains."""
    initial_count = len(asm_engine.assets)
    updated_assets = asm_engine.discover_assets(
        subnet_range=request.subnet_range,
        scan_intensity=request.scan_intensity,
    )
    latest_scan = asm_engine.scan_history[-1]

    await audit_service.log_event(
        db=db,
        action="ASM_SCAN_EXECUTED",
        resource_type="ATTACK_SURFACE",
        resource_id=latest_scan["scan_id"],
        details={
            "subnet_range": request.subnet_range,
            "scan_intensity": request.scan_intensity,
            "assets_discovered": latest_scan["assets_discovered"],
            "total_assets": len(updated_assets),
        },
    )

    return latest_scan


@router.get(
    "/vulnerabilities",
    response_model=List[PrioritizedVulnerabilityResponse],
    summary="List Prioritized Vulnerabilities by Contextual Risk",
)
async def list_vulnerabilities(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: ACTIVE, IN_REMEDIATION, REMEDIATED, RISK_ACCEPTED"),
    priority_filter: Optional[str] = Query(None, alias="priority", description="Filter by priority: P0_CRITICAL, P1_HIGH, P2_MEDIUM, P3_LOW"),
) -> Any:
    """Retrieves vulnerabilities ranked by Contextual Risk Score (EPSS + CVSS + Criticality + Exposure)."""
    if status_filter and status_filter not in [s.value for s in VulnerabilityStatus]:
        valid_statuses = [s.value for s in VulnerabilityStatus]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status filter '{status_filter}'. Valid options: {valid_statuses}",
        )
    if priority_filter and priority_filter not in [p.value for p in VulnerabilityPriority]:
        valid_priorities = [p.value for p in VulnerabilityPriority]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid priority filter '{priority_filter}'. Valid options: {valid_priorities}",
        )
    return asm_engine.get_vulnerabilities(status=status_filter, priority=priority_filter)


@router.post(
    "/vulnerabilities/prioritize",
    response_model=List[PrioritizedVulnerabilityResponse],
    summary="Recalculate Contextual Risk Prioritization",
)
async def prioritize_vulnerabilities(
    request: VulnerabilityPrioritizeRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Recalculates Contextual Risk Scores combining CVSS, EPSS probability, asset tier, and ZTNA controls."""
    results = asm_engine.prioritize_vulnerabilities(recalculate=request.recalculate)

    await audit_service.log_event(
        db=db,
        action="RBVM_PRIORITIZATION_RECALCULATED",
        resource_type="RBVM_ENGINE",
        resource_id="vulnerabilities-catalog",
        details={
            "total_evaluated": len(results),
            "p0_count": sum(1 for v in results if v.get("priority") == VulnerabilityPriority.P0_CRITICAL.value),
        },
    )

    return results


@router.post(
    "/vulnerabilities/{cve_id}/remediate",
    response_model=PrioritizedVulnerabilityResponse,
    summary="Remediate Vulnerability via SOAR Virtual Patch or Host Isolation",
)
async def remediate_vulnerability(
    cve_id: str,
    request: VulnerabilityRemediateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Marks a CVE as remediated or deploys automated SOAR virtual patch compensating controls."""
    try:
        updated_vuln = asm_engine.remediate_vulnerability(
            cve_id=cve_id,
            resolution_notes=request.resolution_notes,
            action=request.action,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="VULNERABILITY_REMEDIATED",
        resource_type="CVE",
        resource_id=cve_id,
        details={
            "action": request.action,
            "notes": request.resolution_notes,
            "status": updated_vuln["status"],
            "asset_id": updated_vuln.get("asset_id"),
        },
    )

    return updated_vuln

