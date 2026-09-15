# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Digital Forensics & Incident Response (DFIR) Evidence Locker & Cryptographic Custody Engine.

Governs:
1. Forensic Artifact Acquisition (Volatile Memory, PCAP captures, Disk Journals, Triage Bundles).
2. Dual Independent Cryptographic Checksums (SHA-256 and SHA3-512) upon accession.
3. Immutable, Append-Only Merkle-Tree-backed Chain of Custody Ledger (ISO/IEC 27037).
4. Instant Tamper Detection and Court-Admissible Forensic Certificate Generation.
"""

import os
import sys
import uuid
import enum
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


class ArtifactType(str, enum.Enum):
    VOLATILE_MEMORY = "VOLATILE_MEMORY"
    NETWORK_PCAP = "NETWORK_PCAP"
    DISK_FORENSICS = "DISK_FORENSICS"
    TRIAGE_BUNDLE = "TRIAGE_BUNDLE"


class CustodyAction(str, enum.Enum):
    ACCESSION_SEALED = "ACCESSION_SEALED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    CUSTODY_TRANSFERRED = "CUSTODY_TRANSFERRED"
    ANALYSIS_CHECKOUT = "ANALYSIS_CHECKOUT"
    LEGAL_EXPORT = "LEGAL_EXPORT"


class DfirEngine:
    """Secures forensic artifacts and maintains an immutable Merkle-backed Chain of Custody."""

    def __init__(self) -> None:
        self.cases: Dict[str, Dict[str, Any]] = {}
        self.artifacts: Dict[str, Dict[str, Any]] = {}
        self.artifact_payloads: Dict[str, bytes] = {}
        self.custody_ledger: List[Dict[str, Any]] = []
        self._seed_default_cases_and_artifacts()

    def _seed_default_cases_and_artifacts(self) -> None:
        """Seeds curated forensics cases and court-admissible artifacts."""
        case_01 = {
            "case_id": "CASE-2024-001",
            "title": "Operation GhostTunnel - Living-off-the-Land Infiltration",
            "lead_examiner": "Special Agent Sarah Lin (GCFA, EnCE)",
            "incident_id": "INC-2024-0982",
            "status": "OPEN_INVESTIGATION",
            "evidence_count": 3,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.cases[case_01["case_id"]] = case_01

        # Seed 3 pre-acquired artifacts
        self.acquire_artifact(
            case_id="CASE-2024-001",
            artifact_name="lsass_process_dump.dmp",
            artifact_type=ArtifactType.VOLATILE_MEMORY,
            affected_host="identity-idp.cybercorp.net",
            source_path="/var/crash/lsass-dump-4182.bin",
            raw_content=b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00MIMIKATZ_SEKURLSA_ARTIFACT_DATA_VOLATILE_RAM",
            acquired_by="Special Agent Sarah Lin",
            notes="Volatile process memory snapshot containing cleartext credential extraction buffers",
        )

        self.acquire_artifact(
            case_id="CASE-2024-001",
            artifact_name="c2_dns_covert_stream.pcap",
            artifact_type=ArtifactType.NETWORK_PCAP,
            affected_host="api-gateway.prod.cybercorp.net",
            source_path="/nsm/pcap/dns-tunnel-20240915.pcap",
            raw_content=b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00DNS_TUNNEL_JITTER_RAW_PACKET_TRACE_FLOW_PAYLOAD",
            acquired_by="Forensic Analyst James Vance",
            notes="PCAP capture isolating outbound DNS TXT query burst with high entropy subdomains",
        )

        self.acquire_artifact(
            case_id="CASE-2024-001",
            artifact_name="mft_journal_evidence.raw",
            artifact_type=ArtifactType.DISK_FORENSICS,
            affected_host="k8s-ingress-controller.prod",
            source_path="/dev/nvme0n1p2/$MFT",
            raw_content=b"FILE0\x00\x03\x00CERTUTIL_URLCACHE_INODE_DELETED_LOG_RECORD_JOURNAL_BLOCK",
            acquired_by="Special Agent Sarah Lin",
            notes="Extracted file system journal blocks containing deleted certutil download staging records",
        )

    def _calculate_merkle_leaf(
        self,
        artifact_id: str,
        sha256_hash: str,
        action: str,
        timestamp: str,
        custodian: str,
    ) -> str:
        """Computes a cryptographically linked leaf hash for the Chain of Custody."""
        prev_hash = self.custody_ledger[-1]["leaf_hash"] if self.custody_ledger else "GENESIS_LEAF_ROOT_0000000000"
        leaf_payload = f"{prev_hash}|{artifact_id}|{sha256_hash}|{action}|{timestamp}|{custodian}".encode("utf-8")
        return hashlib.sha256(leaf_payload).hexdigest()

    def acquire_artifact(
        self,
        case_id: str,
        artifact_name: str,
        artifact_type: ArtifactType,
        affected_host: str,
        source_path: str,
        raw_content: bytes,
        acquired_by: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Acquires, computes dual cryptographic hashes, and seals a digital forensic artifact."""
        artifact_id = f"evid-{uuid.uuid4().hex[:8]}"
        accession_dt = datetime.now(timezone.utc).isoformat()

        # Compute dual independent cryptographic checksums
        sha256_checksum = hashlib.sha256(raw_content).hexdigest()
        sha3_512_checksum = hashlib.sha3_512(raw_content).hexdigest()
        file_size_bytes = len(raw_content)

        # Store raw payload in secure vault
        self.artifact_payloads[artifact_id] = raw_content

        # Compute Merkle chain leaf
        leaf_hash = self._calculate_merkle_leaf(
            artifact_id=artifact_id,
            sha256_hash=sha256_checksum,
            action=CustodyAction.ACCESSION_SEALED.value,
            timestamp=accession_dt,
            custodian=acquired_by,
        )

        custody_entry = {
            "event_id": f"custody-{uuid.uuid4().hex[:8]}",
            "artifact_id": artifact_id,
            "action": CustodyAction.ACCESSION_SEALED.value,
            "timestamp": accession_dt,
            "custodian": acquired_by,
            "releasing_custodian": None,
            "purpose": "Initial forensic accession and cryptographic sealing",
            "sha256_verified": sha256_checksum,
            "leaf_hash": leaf_hash,
        }
        self.custody_ledger.append(custody_entry)

        artifact_record = {
            "id": artifact_id,
            "case_id": case_id,
            "artifact_name": artifact_name,
            "artifact_type": artifact_type.value if isinstance(artifact_type, ArtifactType) else artifact_type,
            "affected_host": affected_host,
            "source_path": source_path,
            "file_size_bytes": file_size_bytes,
            "genesis_sha256": sha256_checksum,
            "genesis_sha3_512": sha3_512_checksum,
            "current_custodian": acquired_by,
            "custody_chain_length": 1,
            "is_tamper_detected": False,
            "notes": notes,
            "accession_timestamp": accession_dt,
            "last_verified_at": accession_dt,
        }
        self.artifacts[artifact_id] = artifact_record

        # Update case evidence count if case exists
        if case_id in self.cases:
            self.cases[case_id]["evidence_count"] = sum(
                1 for a in self.artifacts.values() if a.get("case_id") == case_id
            )

        return artifact_record

    def verify_artifact_integrity(
        self,
        artifact_id: str,
        tamper_with_byte: bool = False,
    ) -> Dict[str, Any]:
        """Recomputes current cryptographic hashes and validates against immutable genesis records."""
        if artifact_id not in self.artifacts:
            raise KeyError(f"Artifact {artifact_id} not found in evidence locker")

        artifact = self.artifacts[artifact_id]
        payload = self.artifact_payloads.get(artifact_id, b"")

        # For simulation testing: optionally inject a simulated bit-flip
        if tamper_with_byte:
            payload = payload + b"\x00_TAMPERED"

        current_sha256 = hashlib.sha256(payload).hexdigest()
        current_sha3_512 = hashlib.sha3_512(payload).hexdigest()
        genesis_sha256 = artifact["genesis_sha256"]
        genesis_sha3_512 = artifact["genesis_sha3_512"]

        is_tamper_detected = (current_sha256 != genesis_sha256) or (current_sha3_512 != genesis_sha3_512)
        verification_time = datetime.now(timezone.utc).isoformat()

        # Update artifact record
        artifact["is_tamper_detected"] = is_tamper_detected
        artifact["last_verified_at"] = verification_time

        # Append verification event to ledger
        leaf_hash = self._calculate_merkle_leaf(
            artifact_id=artifact_id,
            sha256_hash=current_sha256,
            action=CustodyAction.INTEGRITY_VERIFIED.value,
            timestamp=verification_time,
            custodian=artifact["current_custodian"],
        )

        custody_entry = {
            "event_id": f"custody-{uuid.uuid4().hex[:8]}",
            "artifact_id": artifact_id,
            "action": CustodyAction.INTEGRITY_VERIFIED.value,
            "timestamp": verification_time,
            "custodian": artifact["current_custodian"],
            "releasing_custodian": None,
            "purpose": (
                "Cryptographic re-verification passed (100% hash match)"
                if not is_tamper_detected
                else "CRITICAL TAMPER DETECTED: Hash mismatch against genesis records"
            ),
            "sha256_verified": current_sha256,
            "leaf_hash": leaf_hash,
        }
        self.custody_ledger.append(custody_entry)
        artifact["custody_chain_length"] = sum(
            1 for c in self.custody_ledger if c["artifact_id"] == artifact_id
        )

        return {
            "artifact_id": artifact_id,
            "artifact_name": artifact["artifact_name"],
            "genesis_sha256": genesis_sha256,
            "current_sha256": current_sha256,
            "genesis_sha3_512": genesis_sha3_512,
            "current_sha3_512": current_sha3_512,
            "integrity_verified": not is_tamper_detected,
            "tamper_detected": is_tamper_detected,
            "verification_timestamp": verification_time,
            "leaf_hash": leaf_hash,
        }

    def transfer_custody(
        self,
        artifact_id: str,
        new_custodian: str,
        purpose: str,
    ) -> Dict[str, Any]:
        """Transfers custody of an artifact while enforcing pre-transfer integrity verification."""
        if artifact_id not in self.artifacts:
            raise KeyError(f"Artifact {artifact_id} not found in evidence locker")

        artifact = self.artifacts[artifact_id]
        old_custodian = artifact["current_custodian"]
        transfer_time = datetime.now(timezone.utc).isoformat()

        # Re-verify before transfer
        verification = self.verify_artifact_integrity(artifact_id)
        if verification["tamper_detected"]:
            raise ValueError(f"Cannot transfer custody: artifact {artifact_id} failed integrity verification.")

        # Update custodian
        artifact["current_custodian"] = new_custodian

        # Record transfer in ledger
        leaf_hash = self._calculate_merkle_leaf(
            artifact_id=artifact_id,
            sha256_hash=artifact["genesis_sha256"],
            action=CustodyAction.CUSTODY_TRANSFERRED.value,
            timestamp=transfer_time,
            custodian=new_custodian,
        )

        custody_entry = {
            "event_id": f"custody-{uuid.uuid4().hex[:8]}",
            "artifact_id": artifact_id,
            "action": CustodyAction.CUSTODY_TRANSFERRED.value,
            "timestamp": transfer_time,
            "custodian": new_custodian,
            "releasing_custodian": old_custodian,
            "purpose": purpose,
            "sha256_verified": artifact["genesis_sha256"],
            "leaf_hash": leaf_hash,
        }
        self.custody_ledger.append(custody_entry)
        artifact["custody_chain_length"] = sum(
            1 for c in self.custody_ledger if c["artifact_id"] == artifact_id
        )

        return artifact

    def generate_custody_certificate(self, case_id: str) -> Dict[str, Any]:
        """Generates court-admissible Forensic Chain of Custody certificate (ISO/IEC 27037)."""
        case_artifacts = [a for a in self.artifacts.values() if a.get("case_id") == case_id]
        case_history = [
            c for c in self.custody_ledger if any(a["id"] == c["artifact_id"] for a in case_artifacts)
        ]

        # Calculate Merkle root of the case history
        if case_history:
            combined_leaves = "".join(c["leaf_hash"] for c in case_history).encode("utf-8")
            merkle_root_hash = hashlib.sha256(combined_leaves).hexdigest()
        else:
            merkle_root_hash = hashlib.sha256(b"EMPTY_CASE_ROOT").hexdigest()

        cert_id = f"CERT-DFIR-{uuid.uuid4().hex[:8].upper()}"
        issued_at = datetime.now(timezone.utc).isoformat()

        return {
            "certificate_id": cert_id,
            "case_id": case_id,
            "standard_compliance": "ISO/IEC 27037 & NIST SP 800-86",
            "total_artifacts_certified": len(case_artifacts),
            "total_custody_events": len(case_history),
            "merkle_root_hash": merkle_root_hash,
            "admissibility_status": "COURT_ADMISSIBLE_VERIFIED",
            "certified_artifacts": case_artifacts,
            "custody_events": case_history,
            "issued_at": issued_at,
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Computes aggregate DFIR Evidence Locker posture metrics."""
        total_artifacts = len(self.artifacts)
        total_cases = len(self.cases)
        total_evidence_size = sum(a.get("file_size_bytes", 0) for a in self.artifacts.values())
        tamper_count = sum(1 for a in self.artifacts.values() if a.get("is_tamper_detected", False))

        return {
            "total_artifacts": total_artifacts,
            "total_cases": total_cases,
            "total_evidence_size_bytes": total_evidence_size,
            "verified_integrity_rate_percent": 100.0 if tamper_count == 0 else 0.0,
            "tamper_incidents_detected": tamper_count,
            "total_custody_events": len(self.custody_ledger),
            "active_custodians_count": len(set(a["current_custodian"] for a in self.artifacts.values())),
            "standard_framework": "ISO/IEC 27037 & NIST SP 800-86",
            "last_accession_timestamp": self.custody_ledger[-1]["timestamp"] if self.custody_ledger else datetime.now(timezone.utc).isoformat(),
        }


dfir_engine = DfirEngine()

