# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Threat Hunting & Autonomous Detection-as-Code REST API Router."""

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
from backend.app.schemas.threathunting import (
    HuntHypothesisResponse,
    HuntExecutionRequest,
    HuntExecutionResponse,
    DetectionRuleResponse,
    RuleGenerateRequest,
    RuleDeployRequest,
    ThreatHuntingMetricsResponse,
)
from backend.app.threathunting.engine import (
    threathunting_engine,
    RuleFormat,
    RuleStatus,
)
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/threathunting", tags=["Threat Hunting & Autonomous Detection-as-Code"])


@router.get(
    "/metrics",
    response_model=ThreatHuntingMetricsResponse,
    summary="Get Global Threat Hunting & Detection-as-Code Metrics",
)
async def get_hunting_metrics() -> Any:
    """Returns hunting campaigns executed, validation rate, and active Sigma/YARA rule counts."""
    return threathunting_engine.get_metrics()


@router.get(
    "/hypotheses",
    response_model=List[HuntHypothesisResponse],
    summary="List Curated Threat Hunting Hypotheses",
)
async def list_hypotheses() -> Any:
    """Retrieves MITRE ATT&CK aligned hunting hypotheses across C2, Credential Access, and LOLBAS."""
    return list(threathunting_engine.hypotheses.values())


@router.post(
    "/hunts/execute",
    response_model=HuntExecutionResponse,
    summary="Execute Proactive Hypothesis Hunt Across Telemetry",
)
async def execute_hunt(
    request: HuntExecutionRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Executes behavioral queries across historical and streaming telemetry to validate threat hypothesis."""
    try:
        hunt_result = threathunting_engine.execute_hunt(
            hypothesis_id=request.hypothesis_id,
            time_window_hours=request.time_window_hours,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="THREAT_HUNT_EXECUTED",
        resource_type="THREAT_HUNT",
        resource_id=hunt_result["execution_id"],
        details={
            "hypothesis_id": request.hypothesis_id,
            "confidence_score": hunt_result["confidence_score"],
            "findings_count": hunt_result["findings_count"],
            "mitre_technique": hunt_result["mitre_technique"],
        },
    )

    return hunt_result


@router.get(
    "/hunts/history",
    response_model=List[HuntExecutionResponse],
    summary="Get Threat Hunting Execution History",
)
async def get_hunt_history() -> Any:
    """Retrieves past hunting executions, matched IOCs, and affected hosts."""
    return list(reversed(threathunting_engine.hunt_executions))


@router.get(
    "/rules",
    response_model=List[DetectionRuleResponse],
    summary="List Synthesized Detection-as-Code Rules (Sigma & YARA)",
)
async def list_rules(
    format_filter: Optional[str] = Query(None, alias="format", description="Filter by format: SIGMA_YAML, YARA"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: DRAFT, VALIDATED, DEPLOYED_ACTIVE, ARCHIVED"),
) -> Any:
    """Returns detection rules with code syntax, MITRE tags, and deployment statuses."""
    rules = list(threathunting_engine.rules.values())
    if format_filter:
        if format_filter not in [f.value for f in RuleFormat]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid format filter '{format_filter}'. Options: {[f.value for f in RuleFormat]}",
            )
        rules = [r for r in rules if r["format"] == format_filter]

    if status_filter:
        if status_filter not in [s.value for s in RuleStatus]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter '{status_filter}'. Options: {[s.value for s in RuleStatus]}",
            )
        rules = [r for r in rules if r["status"] == status_filter]

    rules.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return rules


@router.post(
    "/rules/generate",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Autonomous Detection Rule Synthesis from Hunt Finding",
)
async def generate_rule(
    request: RuleGenerateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Synthesizes valid Sigma YAML or YARA signature rules directly from confirmed threat hunt observations."""
    try:
        if request.rule_format == RuleFormat.YARA.value:
            new_rule = threathunting_engine.generate_yara_rule(
                hypothesis_id=request.hypothesis_id,
                rule_name=request.title,
            )
        else:
            new_rule = threathunting_engine.generate_sigma_rule(
                hypothesis_id=request.hypothesis_id,
                title=request.title,
                severity=request.severity,
            )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="DETECTION_RULE_SYNTHESIZED",
        resource_type="DETECTION_RULE",
        resource_id=new_rule["id"],
        details={
            "format": new_rule["format"],
            "mitre_technique": new_rule["mitre_technique"],
            "hypothesis_id": request.hypothesis_id,
            "title": new_rule["title"],
        },
    )

    return new_rule


@router.post(
    "/rules/{rule_id}/deploy",
    response_model=DetectionRuleResponse,
    summary="Deploy Synthesized Rule to Active Detection Pipeline",
)
async def deploy_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Activates a Sigma or YARA rule on production detection nodes."""
    try:
        deployed = threathunting_engine.deploy_rule(rule_id=rule_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="DETECTION_RULE_DEPLOYED",
        resource_type="DETECTION_RULE",
        resource_id=rule_id,
        details={
            "title": deployed["title"],
            "format": deployed["format"],
            "status": deployed["status"],
        },
    )

    return deployed

