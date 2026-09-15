# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit test suite for Phase 8 Threat Intelligence Enrichment Engine."""

import os
import sys
import time
import pytest
from datetime import datetime, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
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
from backend.app.threat_intel.cache import IOCCache
from backend.app.threat_intel.feeds.seed_feed import SeedThreatFeed, seed_threat_feed
from backend.app.threat_intel.feeds.stix_adapter import STIX2Adapter
from backend.app.threat_intel.cve_matcher import CVEMatcher, cve_matcher
from backend.app.threat_intel.mitre_mapper import MITREMapper, mitre_mapper
from backend.app.threat_intel.enrichment_service import ThreatEnrichmentService


@pytest.mark.asyncio
async def test_ioc_cache_basic_operations():
    """Validates get, set, delete, and normalization in IOC cache."""
    cache = IOCCache(max_size=100, default_ttl_seconds=3600)

    rec = IOCRecord(
        indicator_type=IndicatorType.IP,
        indicator_value="198.51.100.99",
        reputation_score=85,
        severity=ThreatSeverity.HIGH,
        confidence=ConfidenceLevel.HIGH,
        source="TEST_FEED",
    )

    # Set and retrieve
    await cache.set("198.51.100.99", rec)
    retrieved = await cache.get(" 198.51.100.99 ")  # Test whitespace normalization
    assert retrieved is not None
    assert retrieved.indicator_value == "198.51.100.99"
    assert retrieved.reputation_score == 85

    # Miss check
    miss = await cache.get("192.0.2.1")
    assert miss is None

    # Delete
    await cache.delete("198.51.100.99")
    assert await cache.get("198.51.100.99") is None


@pytest.mark.asyncio
async def test_ioc_cache_lru_eviction():
    """Validates LRU eviction when max_size threshold is exceeded."""
    cache = IOCCache(max_size=3, default_ttl_seconds=3600)

    for i in range(4):
        rec = IOCRecord(
            indicator_type=IndicatorType.IP,
            indicator_value=f"10.0.0.{i}",
            reputation_score=50,
        )
        await cache.set(f"10.0.0.{i}", rec)

    stats = cache.get_stats()
    assert stats["cached_items_count"] == 3
    assert stats["evictions"] == 1
    # 10.0.0.0 should be evicted as oldest
    assert await cache.get("10.0.0.0") is None
    # 10.0.0.3 should still exist
    assert await cache.get("10.0.0.3") is not None


@pytest.mark.asyncio
async def test_ioc_cache_ttl_expiration():
    """Validates TTL expiry invalidates cached records."""
    cache = IOCCache(max_size=10, default_ttl_seconds=1)

    rec = IOCRecord(
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="temp-c2.com",
        reputation_score=90,
    )
    # Set with 1-second TTL
    await cache.set("temp-c2.com", rec, ttl_seconds=1)
    assert await cache.get("temp-c2.com") is not None

    # Wait for TTL expiry
    time.sleep(1.1)
    assert await cache.get("temp-c2.com") is None


@pytest.mark.asyncio
async def test_seed_threat_feed_indicators():
    """Validates curated seed threat feed produces diverse, valid indicators."""
    feed = SeedThreatFeed()
    indicators = await feed.fetch_indicators()
    assert len(indicators) >= 10

    types = set(ind.indicator_type for ind in indicators)
    assert IndicatorType.IP in types
    assert IndicatorType.DOMAIN in types
    assert IndicatorType.URL in types
    assert IndicatorType.SHA256 in types

    # Check known APT29 indicator exists
    c2_ip = next((ind for ind in indicators if ind.indicator_value == "198.51.100.2"), None)
    assert c2_ip is not None
    assert c2_ip.threat_actor == "APT29"
    assert c2_ip.reputation_score >= 90


def test_stix_2_adapter_parsing():
    """Validates STIX 2.1 JSON bundle parsing and relationship mapping."""
    adapter = STIX2Adapter()

    sample_bundle = {
        "type": "bundle",
        "id": "bundle--01234567-89ab-cdef-0123-456789abcdef",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--11111111-2222-3333-4444-555555555555",
                "name": "FIN7",
            },
            {
                "type": "malware",
                "id": "malware--22222222-3333-4444-5555-666666666666",
                "name": "Carbanak",
            },
            {
                "type": "indicator",
                "id": "indicator--33333333-4444-5555-6666-777777777777",
                "name": "Malicious IP Indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.50']",
                "confidence": 85,
                "labels": ["malicious-activity"],
            },
            {
                "type": "relationship",
                "id": "relationship--44444444-5555-6666-7777-888888888888",
                "relationship_type": "indicates",
                "source_ref": "indicator--33333333-4444-5555-6666-777777777777",
                "target_ref": "malware--22222222-3333-4444-5555-666666666666",
            },
        ],
    }

    records = adapter.parse_bundle(sample_bundle)
    assert len(records) == 1
    rec = records[0]
    assert rec.indicator_type == IndicatorType.IP
    assert rec.indicator_value == "198.51.100.50"
    assert rec.malware_family == "Carbanak"
    assert rec.reputation_score >= 80


def test_cve_matcher_port_mapping():
    """Validates CVE matching by destination port."""
    matcher = CVEMatcher()

    # SMB Port 445 -> EternalBlue & SMBGhost
    smb_cves = matcher.match_by_port(445)
    cve_ids = [c.cve_id for c in smb_cves]
    assert "CVE-2017-0144" in cve_ids
    assert "CVE-2020-0796" in cve_ids

    # RDP Port 3389 -> BlueKeep
    rdp_cves = matcher.match_by_port(3389)
    assert any(c.cve_id == "CVE-2019-0708" for c in rdp_cves)

    # Web Port 8080 -> Log4Shell & Spring4Shell
    web_cves = matcher.match_by_port(8080)
    assert any(c.cve_id == "CVE-2021-44228" for c in web_cves)


def test_cve_matcher_context_mapping():
    """Validates context-based matching using attack classification."""
    matcher = CVEMatcher()

    # Lateral movement attack category
    lm_matches = matcher.match_context(attack_category="LATERAL_MOVEMENT")
    lm_ids = [c.cve_id for c in lm_matches]
    assert "CVE-2017-0144" in lm_ids

    # Command injection attack category
    ci_matches = matcher.match_context(attack_category="COMMAND_INJECTION")
    ci_ids = [c.cve_id for c in ci_matches]
    assert "CVE-2021-44228" in ci_ids


def test_mitre_mapper_threat_actor_lookup():
    """Validates threat actor retrieval by primary name and known aliases."""
    mapper = MITREMapper()

    apt28 = mapper.get_actor("APT28")
    assert apt28 is not None
    assert "Fancy Bear" in apt28.aliases

    # Alias lookup
    cozy_bear = mapper.get_actor("Cozy Bear")
    assert cozy_bear is not None
    assert cozy_bear.actor_name == "APT29"

    # Lazarus lookup
    lazarus = mapper.get_actor("ZINC")
    assert lazarus is not None
    assert lazarus.actor_name == "Lazarus Group"


def test_mitre_mapper_attribution():
    """Validates heuristic attribution by signature tools and techniques."""
    mapper = MITREMapper()

    # Tool attribution: Cobalt Strike -> APT29
    attr1 = mapper.attribute_threat(malware_family="Cobalt Strike")
    assert attr1 is not None
    assert attr1.actor_name == "APT29"

    # Tool attribution: WannaCry -> Lazarus Group
    attr2 = mapper.attribute_threat(malware_family="WannaCry")
    assert attr2 is not None
    assert attr2.actor_name == "Lazarus Group"

    # Tactics resolution
    tactics = mapper.get_tactics_for_techniques(["T1190", "T1059", "T1048"])
    assert "Initial Access" in tactics
    assert "Execution" in tactics
    assert "Exfiltration" in tactics


@pytest.mark.asyncio
async def test_threat_enrichment_service_entity():
    """Validates entity enrichment for both malicious C2 and benign entities."""
    service = ThreatEnrichmentService()
    await service.initialize()

    # Malicious seed entity
    res_mal = await service.enrich_entity("198.51.100.2")
    assert res_mal.is_malicious is True
    assert res_mal.reputation_score >= 90
    assert res_mal.threat_actor == "APT29"
    assert "C2" in res_mal.tags

    # Benign / Unknown entity
    res_clean = await service.enrich_entity("192.168.1.100")
    assert res_clean.is_malicious is False
    assert res_clean.reputation_score == 0


@pytest.mark.asyncio
async def test_threat_enrichment_service_alert():
    """Validates alert enrichment, CTI score calculation, and severity escalation."""
    service = ThreatEnrichmentService()
    await service.initialize()

    alert_input = {
        "alert_id": "ALT-TEST-001",
        "title": "Suspicious Outbound Connection",
        "severity": "LOW",
        "source_ip": "10.0.0.5",
        "destination_ip": "198.51.100.2",  # Known APT29 C2
        "destination_port": 445,             # EternalBlue SMB
        "attack_category": "EXFILTRATION",
        "contributing_features": {
            "domain": "cdn-update-auth.com",  # Known malicious phishing domain
        },
    }

    enriched = await service.enrich_alert(alert_input)
    assert "threat_intel" in enriched
    ti = enriched["threat_intel"]

    assert ti["is_known_malicious"] is True
    assert ti["threat_intel_score"] >= 90
    assert ti["threat_actor"] == "APT29"
    assert len(ti["cve_matches"]) > 0
    # Alert severity should be escalated from LOW to CRITICAL due to score >= 95
    assert enriched["severity"] == "CRITICAL"

