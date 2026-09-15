# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""STIX 2.1 / TAXII JSON Bundle Parser & Ingestion Adapter."""

import os
import sys
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.threat_intel.models import (
    IOCRecord,
    IndicatorType,
    ThreatSeverity,
    ConfidenceLevel,
)
from backend.app.threat_intel.feeds.base import BaseFeedProvider


class STIX2Adapter(BaseFeedProvider):
    """Parses and normalizes STIX 2.1 JSON bundles into native IOCRecord objects."""

    def __init__(self, name: str = "STIX 2.1 Feed Adapter", source_id: str = "STIX_FEED"):
        super().__init__(name=name, source_id=source_id)

    def _extract_pattern_value(self, pattern: str) -> tuple[Optional[IndicatorType], Optional[str]]:
        """Extracts indicator type and value from STIX 2.1 pattern syntax."""
        # IPv4 pattern: [ipv4-addr:value = '198.51.100.2']
        ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern, re.IGNORECASE)
        if ip_match:
            return IndicatorType.IP, ip_match.group(1)

        # Domain pattern: [domain-name:value = 'example.com']
        domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern, re.IGNORECASE)
        if domain_match:
            return IndicatorType.DOMAIN, domain_match.group(1)

        # URL pattern: [url:value = 'http://...']
        url_match = re.search(r"url:value\s*=\s*'([^']+)'", pattern, re.IGNORECASE)
        if url_match:
            return IndicatorType.URL, url_match.group(1)

        # SHA-256 pattern: [file:hashes.'SHA-256' = '...']
        sha256_match = re.search(r"file:hashes\.'(?:SHA-256|sha256)'\s*=\s*'([^']+)'", pattern, re.IGNORECASE)
        if sha256_match:
            return IndicatorType.SHA256, sha256_match.group(1)

        # MD5 pattern: [file:hashes.'MD5' = '...']
        md5_match = re.search(r"file:hashes\.'(?:MD5|md5)'\s*=\s*'([^']+)'", pattern, re.IGNORECASE)
        if md5_match:
            return IndicatorType.MD5, md5_match.group(1)

        return None, None

    def parse_bundle(self, bundle: Dict[str, Any]) -> List[IOCRecord]:
        """Parses a complete STIX 2.1 bundle dictionary and correlates indicators with threat actors & malware."""
        if bundle.get("type") != "bundle" or "objects" not in bundle:
            return []

        objects = bundle.get("objects", [])
        indicators_raw = []
        malware_by_id: Dict[str, str] = {}
        actor_by_id: Dict[str, str] = {}
        relationships: List[Dict[str, Any]] = []

        # First pass: categorize objects
        for obj in objects:
            obj_type = obj.get("type")
            if obj_type == "indicator":
                indicators_raw.append(obj)
            elif obj_type == "malware":
                malware_by_id[obj["id"]] = obj.get("name", "Unknown Malware")
            elif obj_type == "threat-actor":
                actor_by_id[obj["id"]] = obj.get("name", "Unknown Threat Actor")
            elif obj_type == "relationship":
                relationships.append(obj)

        # Build relationship map: indicator_id -> (malware_name, actor_name)
        indicator_to_malware: Dict[str, str] = {}
        indicator_to_actor: Dict[str, str] = {}

        for rel in relationships:
            rel_type = rel.get("relationship_type")
            src = rel.get("source_ref")
            target = rel.get("target_ref")

            if rel_type == "indicates" and src and target:
                if target in malware_by_id:
                    indicator_to_malware[src] = malware_by_id[target]
                elif target in actor_by_id:
                    indicator_to_actor[src] = actor_by_id[target]

        # Second pass: normalize indicators
        records: List[IOCRecord] = []
        for ind in indicators_raw:
            pattern = ind.get("pattern", "")
            ind_type, ind_val = self._extract_pattern_value(pattern)
            if not ind_type or not ind_val:
                continue

            # Confidence conversion (STIX 0-100 score)
            stix_conf = ind.get("confidence", 70)
            if stix_conf >= 80:
                conf = ConfidenceLevel.HIGH
                sev = ThreatSeverity.HIGH
                rep_score = 85
            elif stix_conf >= 50:
                conf = ConfidenceLevel.MEDIUM
                sev = ThreatSeverity.MEDIUM
                rep_score = 65
            else:
                conf = ConfidenceLevel.LOW
                sev = ThreatSeverity.LOW
                rep_score = 40

            ind_id = ind.get("id")
            malware = indicator_to_malware.get(ind_id)
            actor = indicator_to_actor.get(ind_id)

            rec = IOCRecord(
                indicator_type=ind_type,
                indicator_value=ind_val,
                reputation_score=rep_score,
                severity=sev,
                confidence=conf,
                threat_actor=actor,
                malware_family=malware,
                source=self.source_id,
                description=ind.get("description") or ind.get("name") or "Imported from STIX 2.1 bundle",
                tags=ind.get("labels", ["STIX_IMPORT"]),
                last_seen=datetime.now(timezone.utc),
            )
            records.append(rec)

        self.last_fetched = datetime.now(timezone.utc)
        self.total_indicators_collected += len(records)
        return records

    async def fetch_indicators(self) -> List[IOCRecord]:
        """BaseFeedProvider implementation - STIX bundles are ingested via `parse_bundle`."""
        return []

