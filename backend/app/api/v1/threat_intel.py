# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Threat Intelligence REST API Router."""

import os
import sys
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.database.session import get_db
from backend.app.models.threat_intel import ThreatIndicator, IndicatorType as DBIndicatorType
from backend.app.threat_intel.models import (
    IndicatorType,
    ThreatSeverity,
    ConfidenceLevel,
    CVEMatch,
    ThreatActorProfile,
    IOCRecord,
    EnrichmentResult,
    IndicatorLookupRequest,
    IndicatorLookupResponse,
    IndicatorCreateRequest,
    IndicatorResponse,
    ThreatIntelStatsResponse,
)
from backend.app.threat_intel.cache import ioc_cache
from backend.app.threat_intel.cve_matcher import cve_matcher
from backend.app.threat_intel.mitre_mapper import mitre_mapper
from backend.app.threat_intel.enrichment_service import threat_enrichment_service

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.post("/lookup", response_model=IndicatorLookupResponse)
async def lookup_indicators(
    payload: IndicatorLookupRequest,
    db: AsyncSession = Depends(get_db),
) -> IndicatorLookupResponse:
    """Enriches and evaluates reputation for a list of IP addresses, domains, or file hashes."""
    results: Dict[str, EnrichmentResult] = {}
    malicious_count = 0

    for ind in payload.indicators:
        res = await threat_enrichment_service.enrich_entity(ind, db_session=db)
        results[ind] = res
        if res.is_malicious:
            malicious_count += 1

    return IndicatorLookupResponse(
        total_queried=len(payload.indicators),
        malicious_found=malicious_count,
        results=results,
    )


@router.get("/indicators", response_model=List[IndicatorResponse])
async def list_indicators(
    indicator_type: Optional[IndicatorType] = None,
    min_score: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[IndicatorResponse]:
    """Lists persistent threat intelligence indicators with multi-attribute filtering."""
    query = select(ThreatIndicator).order_by(desc(ThreatIndicator.last_updated))

    if indicator_type:
        query = query.where(ThreatIndicator.indicator_type == indicator_type.value)
    if min_score > 0:
        query = query.where(ThreatIndicator.reputation_score >= min_score)

    query = query.offset(offset).limit(limit)
    res = await db.execute(query)
    db_indicators = res.scalars().all()

    output = []
    for item in db_indicators:
        itype = getattr(item.indicator_type, "value", str(item.indicator_type))
        output.append(
            IndicatorResponse(
                id=str(item.id),
                indicator_type=itype,
                indicator_value=str(item.indicator_value),
                reputation_score=int(item.reputation_score),
                threat_actor=item.threat_actor,
                source=str(item.source),
                description=item.description,
                last_updated=item.last_updated,
            )
        )
    return output


@router.post("/indicators", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
async def create_indicator(
    payload: IndicatorCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> IndicatorResponse:
    """Manually registers a new Indicator of Compromise (analyst submission)."""
    # Check if indicator value already exists
    existing = await db.execute(
        select(ThreatIndicator).where(ThreatIndicator.indicator_value == payload.indicator_value.strip())
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Indicator '{payload.indicator_value}' already exists in database",
        )

    try:
        db_type = DBIndicatorType[payload.indicator_type.value]
    except KeyError:
        db_type = DBIndicatorType.IP

    new_ind = ThreatIndicator(
        indicator_type=db_type,
        indicator_value=payload.indicator_value.strip(),
        reputation_score=payload.reputation_score,
        threat_actor=payload.threat_actor,
        source=payload.source,
        description=payload.description,
    )
    db.add(new_ind)
    await db.commit()
    await db.refresh(new_ind)

    # Immediately populate cache
    rec = IOCRecord(
        indicator_type=payload.indicator_type,
        indicator_value=new_ind.indicator_value,
        reputation_score=new_ind.reputation_score,
        severity=ThreatSeverity.HIGH if new_ind.reputation_score >= 70 else ThreatSeverity.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        threat_actor=new_ind.threat_actor,
        source=new_ind.source,
        description=new_ind.description,
        tags=payload.tags or ["ANALYST_SUBMISSION"],
    )
    await ioc_cache.set(new_ind.indicator_value, rec)

    itype = getattr(new_ind.indicator_type, "value", str(new_ind.indicator_type))
    return IndicatorResponse(
        id=str(new_ind.id),
        indicator_type=itype,
        indicator_value=str(new_ind.indicator_value),
        reputation_score=int(new_ind.reputation_score),
        threat_actor=new_ind.threat_actor,
        source=str(new_ind.source),
        description=new_ind.description,
        last_updated=new_ind.last_updated,
    )


@router.get("/stats", response_model=ThreatIntelStatsResponse)
async def get_threat_intel_stats(
    db: AsyncSession = Depends(get_db),
) -> ThreatIntelStatsResponse:
    """Returns aggregated CTI cache and operational database metrics."""
    await threat_enrichment_service.initialize(db)
    cache_metrics = ioc_cache.get_stats()

    # Query DB indicator count
    res = await db.execute(select(ThreatIndicator))
    total_db = len(res.scalars().all())

    actors = mitre_mapper.list_all_actors()
    cves = cve_matcher.get_all_cves()

    return ThreatIntelStatsResponse(
        total_indicators_cached=cache_metrics["cached_items_count"],
        total_database_indicators=total_db,
        cache_hits=cache_metrics["hits"],
        cache_misses=cache_metrics["misses"],
        cache_hit_ratio=cache_metrics["hit_ratio"],
        active_feeds=["SEED_INTEL_FEED", "STIX_2.1_INGESTION", "LOCAL_DATABASE"],
        threat_actors_tracked=len(actors),
        cves_mapped=len(cves),
    )


@router.get("/actors", response_model=List[ThreatActorProfile])
async def list_threat_actors() -> List[ThreatActorProfile]:
    """Returns MITRE ATT&CK attributed adversary groups."""
    return mitre_mapper.list_all_actors()


@router.get("/cves", response_model=List[CVEMatch])
async def list_cves(port: Optional[int] = None) -> List[CVEMatch]:
    """Returns mapped high-impact CVEs, optionally filtered by port."""
    if port:
        return cve_matcher.match_by_port(port)
    return cve_matcher.get_all_cves()

