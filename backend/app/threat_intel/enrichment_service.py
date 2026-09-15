# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Threat Intelligence Enrichment Orchestrator Service."""

import os
import sys
import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.threat_intel.models import (
    IOCRecord,
    IndicatorType,
    ThreatSeverity,
    ConfidenceLevel,
    EnrichmentResult,
)
from backend.app.threat_intel.cache import ioc_cache
from backend.app.threat_intel.feeds.seed_feed import seed_threat_feed
from backend.app.threat_intel.cve_matcher import cve_matcher
from backend.app.threat_intel.mitre_mapper import mitre_mapper
from backend.app.models.threat_intel import ThreatIndicator


class ThreatEnrichmentService:
    """Coordinates IOC caching, database queries, CVE matching, and threat actor attribution."""

    def __init__(self):
        self._initialized = False

    async def initialize(self, db_session: Optional[AsyncSession] = None) -> None:
        """Loads seed feed and database indicators into the fast dual-tier cache."""
        if self._initialized:
            return

        # 1. Ingest curated seed indicators
        seed_records = await seed_threat_feed.fetch_indicators()
        await ioc_cache.bulk_set(seed_records)

        # 2. Ingest persistent DB indicators if session provided
        if db_session:
            try:
                stmt = select(ThreatIndicator)
                res = await db_session.execute(stmt)
                db_inds = res.scalars().all()
                db_records = []
                for ind in db_inds:
                    try:
                        itype = IndicatorType(ind.indicator_type.value if hasattr(ind.indicator_type, "value") else str(ind.indicator_type))
                    except Exception:
                        itype = IndicatorType.IP

                    rec = IOCRecord(
                        indicator_type=itype,
                        indicator_value=ind.indicator_value,
                        reputation_score=ind.reputation_score,
                        severity=ThreatSeverity.HIGH if ind.reputation_score >= 70 else ThreatSeverity.MEDIUM,
                        confidence=ConfidenceLevel.HIGH,
                        threat_actor=ind.threat_actor,
                        source=ind.source,
                        description=ind.description,
                        tags=["DB_STORED"],
                        last_seen=ind.last_updated or datetime.now(timezone.utc),
                    )
                    db_records.append(rec)
                if db_records:
                    await ioc_cache.bulk_set(db_records)
            except Exception:
                pass

        self._initialized = True

    def detect_indicator_type(self, value: str) -> IndicatorType:
        """Infers indicator type from string formatting."""
        val = value.strip()
        # IP check
        try:
            ipaddress.ip_address(val)
            return IndicatorType.IP
        except ValueError:
            pass

        # Hash check
        if re.match(r"^[a-fA-F0-9]{64}$", val):
            return IndicatorType.SHA256
        if re.match(r"^[a-fA-F0-9]{32}$", val):
            return IndicatorType.MD5
        if re.match(r"^[a-fA-F0-9]{40}$", val):
            return IndicatorType.SHA1

        # URL check
        if val.startswith("http://") or val.startswith("https://") or val.startswith("ldap://"):
            return IndicatorType.URL

        # CVE check
        if re.match(r"^CVE-\d{4}-\d+$", val, re.IGNORECASE):
            return IndicatorType.CVE

        # Default to domain
        return IndicatorType.DOMAIN

    async def enrich_entity(
        self,
        entity_value: str,
        entity_type: Optional[IndicatorType] = None,
        db_session: Optional[AsyncSession] = None,
    ) -> EnrichmentResult:
        """Enriches a single entity (IP, domain, hash, or URL)."""
        await self.initialize(db_session)
        val = entity_value.strip()
        itype = entity_type or self.detect_indicator_type(val)

        # 1. Check IOC Cache
        cached_record = await ioc_cache.get(val)
        if cached_record:
            is_mal = cached_record.reputation_score >= 60
            tactics = []
            techniques = []
            actor_profile = None

            if cached_record.threat_actor:
                actor_profile = mitre_mapper.get_actor(cached_record.threat_actor)
                if actor_profile:
                    techniques = actor_profile.known_ttp_ids
                    tactics = mitre_mapper.get_tactics_for_techniques(techniques)

            return EnrichmentResult(
                entity=val,
                entity_type=itype,
                is_malicious=is_mal,
                reputation_score=cached_record.reputation_score,
                severity=cached_record.severity,
                confidence=cached_record.confidence,
                threat_actor=cached_record.threat_actor,
                malware_family=cached_record.malware_family,
                cve_matches=[],
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                sources=[cached_record.source],
                tags=cached_record.tags,
            )

        # 2. Check Database if session provided
        if db_session:
            try:
                stmt = select(ThreatIndicator).where(ThreatIndicator.indicator_value == val)
                res = await db_session.execute(stmt)
                db_ind = res.scalar_one_or_none()
                if db_ind:
                    rec = IOCRecord(
                        indicator_type=itype,
                        indicator_value=db_ind.indicator_value,
                        reputation_score=db_ind.reputation_score,
                        severity=ThreatSeverity.HIGH if db_ind.reputation_score >= 70 else ThreatSeverity.MEDIUM,
                        confidence=ConfidenceLevel.HIGH,
                        threat_actor=db_ind.threat_actor,
                        source=db_ind.source,
                        description=db_ind.description,
                        tags=["DB_LOOKUP"],
                    )
                    await ioc_cache.set(val, rec)
                    is_mal = rec.reputation_score >= 60
                    return EnrichmentResult(
                        entity=val,
                        entity_type=itype,
                        is_malicious=is_mal,
                        reputation_score=rec.reputation_score,
                        severity=rec.severity,
                        confidence=rec.confidence,
                        threat_actor=rec.threat_actor,
                        sources=[rec.source],
                        tags=rec.tags,
                    )
            except Exception:
                pass

        # 3. Benign / Unknown entity negative cache entry
        clean_rec = IOCRecord(
            indicator_type=itype,
            indicator_value=val,
            reputation_score=0,
            severity=ThreatSeverity.LOW,
            confidence=ConfidenceLevel.LOW,
            source="CLEAN_BASELINE",
            description="No malicious reputation observed in threat intelligence feeds",
        )
        # Cache clean items with 30 min TTL
        await ioc_cache.set(val, clean_rec, ttl_seconds=1800)

        return EnrichmentResult(
            entity=val,
            entity_type=itype,
            is_malicious=False,
            reputation_score=0,
            severity=ThreatSeverity.LOW,
            confidence=ConfidenceLevel.LOW,
            sources=["LOCAL_INTEL"],
            tags=["UNKNOWN_OR_BENIGN"],
        )

    async def enrich_alert(
        self,
        alert_dict: Dict[str, Any],
        db_session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Deeply enriches a detection alert dictionary with CTI, CVE, and MITRE metadata."""
        await self.initialize(db_session)
        enriched = dict(alert_dict)

        src_ip = alert_dict.get("source_ip")
        dst_ip = alert_dict.get("destination_ip")
        dst_port = alert_dict.get("destination_port") or alert_dict.get("dst_port")
        attack_cat = alert_dict.get("attack_category") or alert_dict.get("classification") or alert_dict.get("scenario")

        # Normalize port to integer if present
        if dst_port is not None:
            try:
                dst_port = int(dst_port)
            except (ValueError, TypeError):
                dst_port = None

        matched_results: List[EnrichmentResult] = []
        max_reputation = 0
        attributed_actor = None
        malware_family = None
        all_tags = set()
        sources = set()

        # 1. Cross-reference source IP
        if src_ip:
            res = await self.enrich_entity(src_ip, IndicatorType.IP, db_session=db_session)
            if res.is_malicious:
                matched_results.append(res)
                max_reputation = max(max_reputation, res.reputation_score)
                if res.threat_actor:
                    attributed_actor = res.threat_actor
                if res.malware_family:
                    malware_family = res.malware_family
                all_tags.update(res.tags)
                sources.update(res.sources)

        # 2. Cross-reference destination IP
        if dst_ip:
            res = await self.enrich_entity(dst_ip, IndicatorType.IP, db_session=db_session)
            if res.is_malicious:
                matched_results.append(res)
                max_reputation = max(max_reputation, res.reputation_score)
                if not attributed_actor and res.threat_actor:
                    attributed_actor = res.threat_actor
                if not malware_family and res.malware_family:
                    malware_family = res.malware_family
                all_tags.update(res.tags)
                sources.update(res.sources)

        # 3. Cross-reference contributing features for hashes or domains
        features = alert_dict.get("contributing_features") or alert_dict.get("features") or {}
        if isinstance(features, dict):
            for k, v in features.items():
                if isinstance(v, str) and len(v) >= 8:
                    if k in ("domain", "hostname", "c2_domain", "query"):
                        res = await self.enrich_entity(v, IndicatorType.DOMAIN, db_session=db_session)
                        if res.is_malicious:
                            matched_results.append(res)
                            max_reputation = max(max_reputation, res.reputation_score)
                            all_tags.update(res.tags)
                    elif k in ("file_hash", "md5", "sha256", "payload_hash"):
                        res = await self.enrich_entity(v, db_session=db_session)
                        if res.is_malicious:
                            matched_results.append(res)
                            max_reputation = max(max_reputation, res.reputation_score)
                            all_tags.update(res.tags)

        # 4. Correlate Vulnerabilities (CVE Matcher)
        cve_matches = cve_matcher.match_context(port=dst_port, attack_category=attack_cat)

        # 5. MITRE ATT&CK Attribution
        actor_profile = mitre_mapper.attribute_threat(
            actor_hint=attributed_actor,
            malware_family=malware_family,
            attack_category=attack_cat,
        )
        if actor_profile:
            attributed_actor = actor_profile.actor_name

        # Calculate composite threat intelligence score
        base_rep = max_reputation
        if cve_matches:
            # Boost score if targeting known critical CVEs
            highest_cvss = max(c.cvss_score for c in cve_matches)
            cve_boost = int(highest_cvss * 4)  # Up to +40 points
            base_rep = min(100, max(base_rep, 50 + cve_boost // 2))

        # Assemble enrichment metadata
        ti_metadata = {
            "threat_intel_score": base_rep,
            "threat_actor": attributed_actor,
            "malware_family": malware_family,
            "is_known_malicious": len(matched_results) > 0 or base_rep >= 60,
            "cve_matches": [c.model_dump() for c in cve_matches],
            "matched_indicators_count": len(matched_results),
            "sources": sorted(list(sources)),
            "tags": sorted(list(all_tags)),
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

        enriched["threat_intel"] = ti_metadata

        # Escalate alert severity if corroborated by high-confidence threat intelligence
        if base_rep >= 85 and enriched.get("severity") in ("LOW", "MEDIUM", None):
            enriched["severity"] = "HIGH"
        if base_rep >= 95 and enriched.get("severity") != "CRITICAL":
            enriched["severity"] = "CRITICAL"

        return enriched


threat_enrichment_service = ThreatEnrichmentService()

