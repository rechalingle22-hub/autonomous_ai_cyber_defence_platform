# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Digital Forensics & Incident Response (DFIR) REST API Router."""

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
from backend.app.schemas.dfir import (
    ForensicArtifactResponse,
    ArtifactAcquisitionRequest,
    CustodyTransferRequest,
    IntegrityVerificationResponse,
    CustodyCertificateResponse,
    ForensicCaseResponse,
    DfirMetricsResponse,
)
from backend.app.dfir.engine import (
    dfir_engine,
    ArtifactType,
)
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/dfir", tags=["Digital Forensics & Cryptographic Custody (DFIR)"])


@router.get(
    "/metrics",
    response_model=DfirMetricsResponse,
    summary="Get Global DFIR Evidence Locker & Custody Metrics",
)
async def get_dfir_metrics() -> Any:
    """Returns total preserved artifacts, verified integrity rate, evidence size, and custody events."""
    return dfir_engine.get_metrics()


@router.get(
    "/cases",
    response_model=List[ForensicCaseResponse],
    summary="List Active Forensic Cases",
)
async def list_cases() -> Any:
    """Retrieves all forensic cases linked to security incidents with evidence tallies."""
    return list(dfir_engine.cases.values())


@router.post(
    "/artifacts/acquire",
    response_model=ForensicArtifactResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Acquire and Cryptographically Seal Forensic Artifact",
)
async def acquire_artifact(
    request: ArtifactAcquisitionRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Acquires, computes dual SHA-256 and SHA3-512 checksums, and appends artifact to Merkle custody chain."""
    try:
        art_type = ArtifactType(request.artifact_type)
    except ValueError:
        valid_types = [t.value for t in ArtifactType]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid artifact_type '{request.artifact_type}'. Valid options: {valid_types}",
        )

    raw_bytes = request.content_text.encode("utf-8")

    artifact = dfir_engine.acquire_artifact(
        case_id=request.case_id,
        artifact_name=request.artifact_name,
        artifact_type=art_type,
        affected_host=request.affected_host,
        source_path=request.source_path,
        raw_content=raw_bytes,
        acquired_by=request.acquired_by,
        notes=request.notes or "",
    )

    await audit_service.log_event(
        db=db,
        action="FORENSIC_ARTIFACT_ACQUIRED",
        resource_type="FORENSIC_ARTIFACT",
        resource_id=artifact["id"],
        details={
            "case_id": request.case_id,
            "artifact_name": request.artifact_name,
            "genesis_sha256": artifact["genesis_sha256"],
            "acquired_by": request.acquired_by,
        },
    )

    return artifact


@router.get(
    "/artifacts",
    response_model=List[ForensicArtifactResponse],
    summary="List Preserved Forensic Evidence Artifacts",
)
async def list_artifacts(
    case_id: Optional[str] = Query(None, description="Filter by forensic case ID"),
    artifact_type: Optional[str] = Query(None, description="Filter by type: VOLATILE_MEMORY, NETWORK_PCAP, DISK_FORENSICS, TRIAGE_BUNDLE"),
) -> Any:
    """Returns artifacts in the evidence locker with cryptographic hashes and custody status."""
    artifacts = list(dfir_engine.artifacts.values())
    if case_id:
        artifacts = [a for a in artifacts if a.get("case_id") == case_id]
    if artifact_type:
        if artifact_type not in [t.value for t in ArtifactType]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid artifact_type filter '{artifact_type}'. Options: {[t.value for t in ArtifactType]}",
            )
        artifacts = [a for a in artifacts if a.get("artifact_type") == artifact_type]

    artifacts.sort(key=lambda x: x.get("accession_timestamp", ""), reverse=True)
    return artifacts


@router.get(
    "/artifacts/{artifact_id}",
    response_model=ForensicArtifactResponse,
    summary="Get Specific Forensic Artifact Details",
)
async def get_artifact(artifact_id: str) -> Any:
    """Retrieves metadata, custody chain length, and genesis checksums for a specific artifact."""
    if artifact_id not in dfir_engine.artifacts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact {artifact_id} not found in evidence locker",
        )
    return dfir_engine.artifacts[artifact_id]


@router.post(
    "/artifacts/{artifact_id}/verify",
    response_model=IntegrityVerificationResponse,
    summary="Cryptographically Re-Verify Artifact Integrity",
)
async def verify_artifact_integrity(
    artifact_id: str,
    tamper_test: bool = Query(False, description="Simulate bit-flip to test tamper detection"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Recomputes current payload hashes and verifies against immutable genesis checksums."""
    try:
        verification = dfir_engine.verify_artifact_integrity(
            artifact_id=artifact_id,
            tamper_with_byte=tamper_test,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="FORENSIC_INTEGRITY_VERIFIED",
        resource_type="FORENSIC_ARTIFACT",
        resource_id=artifact_id,
        details={
            "integrity_verified": verification["integrity_verified"],
            "tamper_detected": verification["tamper_detected"],
            "current_sha256": verification["current_sha256"],
        },
    )

    return verification


@router.post(
    "/artifacts/{artifact_id}/transfer",
    response_model=ForensicArtifactResponse,
    summary="Transfer Forensic Artifact Custody",
)
async def transfer_custody(
    artifact_id: str,
    request: CustodyTransferRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Transfers evidence custody to new examiner after mandatory pre-transfer integrity verification."""
    try:
        artifact = dfir_engine.transfer_custody(
            artifact_id=artifact_id,
            new_custodian=request.new_custodian,
            purpose=request.purpose,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    await audit_service.log_event(
        db=db,
        action="CUSTODY_TRANSFERRED",
        resource_type="FORENSIC_ARTIFACT",
        resource_id=artifact_id,
        details={
            "new_custodian": request.new_custodian,
            "purpose": request.purpose,
            "chain_length": artifact["custody_chain_length"],
        },
    )

    return artifact


@router.get(
    "/cases/{case_id}/certificate",
    response_model=CustodyCertificateResponse,
    summary="Export Court-Admissible Chain of Custody Certificate (ISO/IEC 27037)",
)
async def get_custody_certificate(case_id: str) -> Any:
    """Generates court-admissible Chain of Custody audit certificate with Merkle root hash."""
    return dfir_engine.generate_custody_certificate(case_id=case_id)

