# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic Schemas for DFIR Evidence Locker & Cryptographic Custody Engine."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class CustodyEventResponse(BaseModel):
    event_id: str
    artifact_id: str
    action: str
    timestamp: str
    custodian: str
    releasing_custodian: Optional[str] = None
    purpose: str
    sha256_verified: str
    leaf_hash: str


class ForensicArtifactResponse(BaseModel):
    id: str
    case_id: str
    artifact_name: str
    artifact_type: str
    affected_host: str
    source_path: str
    file_size_bytes: int
    genesis_sha256: str
    genesis_sha3_512: str
    current_custodian: str
    custody_chain_length: int
    is_tamper_detected: bool
    notes: Optional[str] = None
    accession_timestamp: str
    last_verified_at: str


class ArtifactAcquisitionRequest(BaseModel):
    case_id: str = Field("CASE-2024-001", description="Forensic Case identifier")
    artifact_name: str = Field(..., description="Filename or artifact identifier")
    artifact_type: str = Field("VOLATILE_MEMORY", description="Artifact category: VOLATILE_MEMORY, NETWORK_PCAP, DISK_FORENSICS, TRIAGE_BUNDLE")
    affected_host: str = Field(..., description="Target host or asset hostname")
    source_path: str = Field("/tmp/forensic-capture.raw", description="Original filesystem or device source path")
    content_text: str = Field("FORENSIC_RAW_ACQUISITION_PAYLOAD_EVIDENCE", description="Artifact payload content to be cryptographically sealed")
    acquired_by: str = Field("Special Agent Sarah Lin", description="Forensic examiner or automated acquisition agent name")
    notes: Optional[str] = Field("", description="Triage notes and evidentiary context")


class CustodyTransferRequest(BaseModel):
    new_custodian: str = Field(..., description="Receiving examiner or secure vault custodian name")
    purpose: str = Field("Transferred to Secondary Forensics Lab for Deep String Analysis", description="Custody transfer rationale")


class IntegrityVerificationResponse(BaseModel):
    artifact_id: str
    artifact_name: str
    genesis_sha256: str
    current_sha256: str
    genesis_sha3_512: str
    current_sha3_512: str
    integrity_verified: bool
    tamper_detected: bool
    verification_timestamp: str
    leaf_hash: str


class CustodyCertificateResponse(BaseModel):
    certificate_id: str
    case_id: str
    standard_compliance: str
    total_artifacts_certified: int
    total_custody_events: int
    merkle_root_hash: str
    admissibility_status: str
    certified_artifacts: List[Dict[str, Any]]
    custody_events: List[Dict[str, Any]]
    issued_at: str


class ForensicCaseResponse(BaseModel):
    case_id: str
    title: str
    lead_examiner: str
    incident_id: str
    status: str
    evidence_count: int
    created_at: str


class DfirMetricsResponse(BaseModel):
    total_artifacts: int
    total_cases: int
    total_evidence_size_bytes: int
    verified_integrity_rate_percent: float
    tamper_incidents_detected: int
    total_custody_events: int
    active_custodians_count: int
    standard_framework: str
    last_accession_timestamp: str

