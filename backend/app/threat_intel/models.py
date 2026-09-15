# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Threat Intelligence Pydantic schemas, Enums, and Data Transfer Objects."""

import os
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


class IndicatorType(str, Enum):
    """Supported indicator of compromise (IOC) types."""
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    CVE = "CVE"


class ThreatSeverity(str, Enum):
    """Categorical threat severity."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    """CTI source confidence rating."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CVEMatch(BaseModel):
    """Vulnerability mapping model."""
    cve_id: str = Field(..., description="Common Vulnerabilities and Exposures identifier (e.g. CVE-2021-44228)")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="Common Vulnerability Scoring System v3 score")
    severity: ThreatSeverity = Field(default=ThreatSeverity.MEDIUM, description="Calculated threat severity")
    description: str = Field(..., description="Vulnerability description and impact")
    affected_service: Optional[str] = Field(default=None, description="Impacted network protocol or software service")
    port: Optional[int] = Field(default=None, description="Standard or observed service port")
    exploit_available: bool = Field(default=False, description="Whether known public exploit code exists")
    remediation: Optional[str] = Field(default=None, description="Recommended patching or mitigation action")


class ThreatActorProfile(BaseModel):
    """Adversary group profile based on MITRE ATT&CK."""
    actor_name: str = Field(..., description="Primary adversary group name (e.g. APT28, Lazarus Group)")
    aliases: List[str] = Field(default_factory=list, description="Known alternate names or tracking monikers")
    country_of_origin: Optional[str] = Field(default=None, description="Suspected state sponsor or region")
    primary_motivation: str = Field(default="ESPIONAGE", description="Primary objective: ESPIONAGE, FINANCIAL, SABOTAGE")
    target_sectors: List[str] = Field(default_factory=list, description="Targeted industry verticals or infrastructure")
    known_ttp_ids: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs (e.g. T1110, T1046)")
    signature_tools: List[str] = Field(default_factory=list, description="Custom malware or tools utilized")


class IOCRecord(BaseModel):
    """Normalized Indicator of Compromise record."""
    indicator_type: IndicatorType = Field(..., description="Type of indicator (IP, DOMAIN, HASH, etc.)")
    indicator_value: str = Field(..., description="The indicator value (e.g. 198.51.100.2)")
    reputation_score: int = Field(default=50, ge=0, le=100, description="Reputation score: 0 (benign) to 100 (malicious)")
    severity: ThreatSeverity = Field(default=ThreatSeverity.MEDIUM, description="Associated threat severity")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM, description="Confidence in this intelligence")
    threat_actor: Optional[str] = Field(default=None, description="Associated APT or cybercriminal group")
    malware_family: Optional[str] = Field(default=None, description="Associated malware family or tool")
    campaign: Optional[str] = Field(default=None, description="Campaign identifier or operation name")
    source: str = Field(default="LOCAL_INTEL", description="Feed provider or origin of intelligence")
    description: Optional[str] = Field(default=None, description="Contextual threat narrative")
    tags: List[str] = Field(default_factory=list, description="Taxonomy tags (e.g. C2, TOR, BOTNET, RANSOMWARE)")
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp indicator was last verified")


class EnrichmentResult(BaseModel):
    """Aggregated threat intelligence enrichment result for an entity or alert."""
    entity: str = Field(..., description="Analyzed entity (IP, domain, or hash)")
    entity_type: IndicatorType = Field(..., description="Identified entity type")
    is_malicious: bool = Field(default=False, description="Flag indicating if reputation score exceeds threshold")
    reputation_score: int = Field(default=0, ge=0, le=100, description="Calculated composite reputation score (0-100)")
    severity: ThreatSeverity = Field(default=ThreatSeverity.LOW, description="Severity rating")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.LOW, description="Confidence level")
    threat_actor: Optional[str] = Field(default=None, description="Attributed adversary group")
    malware_family: Optional[str] = Field(default=None, description="Associated malware family")
    cve_matches: List[CVEMatch] = Field(default_factory=list, description="Correlated CVE vulnerabilities")
    mitre_tactics: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK tactics")
    mitre_techniques: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK technique IDs")
    sources: List[str] = Field(default_factory=list, description="CTI feeds corroborating this finding")
    tags: List[str] = Field(default_factory=list, description="Threat categorization tags")
    enrichment_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time of enrichment execution",
    )


# API Request/Response Models
class IndicatorLookupRequest(BaseModel):
    """Request payload for single or bulk indicator lookup."""
    indicators: List[str] = Field(..., min_length=1, max_length=100, description="List of indicators (IPs, domains, hashes)")


class IndicatorLookupResponse(BaseModel):
    """Response payload for indicator lookup."""
    total_queried: int = Field(..., description="Number of indicators queried")
    malicious_found: int = Field(..., description="Number of malicious indicators identified")
    results: Dict[str, EnrichmentResult] = Field(..., description="Enrichment results keyed by indicator value")


class IndicatorCreateRequest(BaseModel):
    """Analyst submission payload for new IOC."""
    indicator_type: IndicatorType = Field(...)
    indicator_value: str = Field(..., min_length=1, max_length=255)
    reputation_score: int = Field(default=75, ge=0, le=100)
    threat_actor: Optional[str] = Field(default=None)
    malware_family: Optional[str] = Field(default=None)
    source: str = Field(default="ANALYST_SUBMISSION")
    description: Optional[str] = Field(default=None)
    tags: List[str] = Field(default_factory=list)


class IndicatorResponse(BaseModel):
    """Output representation of stored threat indicator."""
    id: str
    indicator_type: str
    indicator_value: str
    reputation_score: int
    threat_actor: Optional[str]
    source: str
    description: Optional[str]
    last_updated: datetime


class ThreatIntelStatsResponse(BaseModel):
    """Platform threat intelligence operational metrics."""
    total_indicators_cached: int = Field(...)
    total_database_indicators: int = Field(...)
    cache_hits: int = Field(...)
    cache_misses: int = Field(...)
    cache_hit_ratio: float = Field(...)
    active_feeds: List[str] = Field(...)
    threat_actors_tracked: int = Field(...)
    cves_mapped: int = Field(...)

