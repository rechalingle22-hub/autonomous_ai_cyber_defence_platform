# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportMissingModuleSource=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportCallIssue=false
# pyright: reportArgumentType=false
# pyright: reportAssignmentType=false
# pyright: reportUnusedImport=false
# pyright: reportUnusedVariable=false
# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""UEBA REST API router for entity behavioral profiling and impossible travel detection."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path:
        sys.path.insert(0, p)

from typing import Dict, Any, List, Optional  # type: ignore
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, status  # type: ignore
from pydantic import BaseModel, Field  # type: ignore

try:
    from ...ueba.engine import ueba_engine  # type: ignore
    from ...ueba.baseline import baseline_store  # type: ignore
    from ...ueba.geo_velocity import GeoPoint, detect_impossible_travel  # type: ignore
except (ImportError, ValueError):
    from backend.app.ueba.engine import ueba_engine  # type: ignore
    from backend.app.ueba.baseline import baseline_store  # type: ignore
    from backend.app.ueba.geo_velocity import GeoPoint, detect_impossible_travel  # type: ignore
from backend.app.ueba.engine import ueba_engine
from backend.app.ueba.baseline import baseline_store
from backend.app.ueba.geo_velocity import GeoPoint, detect_impossible_travel

router = APIRouter(prefix="/ueba", tags=["User & Entity Behavior Analytics (UEBA)"])


class UEBAEvaluateRequest(BaseModel):
    user_id: Optional[str] = Field(default=None, description="Username or security principal identifier")
    source_ip: Optional[str] = Field(default=None, description="Originating client IP or host")
    destination_port: Optional[int] = Field(default=None, description="Target destination port")
    timestamp: Optional[str] = Field(default=None, description="Event occurrence timestamp (ISO format)")
    features: Dict[str, Any] = Field(default_factory=dict, description="Numerical flow features")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata including optional geo coordinates")


class GeoTravelRequest(BaseModel):
    origin_lat: float = Field(..., ge=-90.0, le=90.0, description="Latitude of first observation")
    origin_lon: float = Field(..., ge=-180.0, le=180.0, description="Longitude of first observation")
    origin_timestamp: str = Field(..., description="Timestamp of first observation (ISO format)")
    origin_city: Optional[str] = Field(default="", description="Origin city name")

    dest_lat: float = Field(..., ge=-90.0, le=90.0, description="Latitude of second observation")
    dest_lon: float = Field(..., ge=-180.0, le=180.0, description="Longitude of second observation")
    dest_timestamp: str = Field(..., description="Timestamp of second observation (ISO format)")
    dest_city: Optional[str] = Field(default="", description="Destination city name")

    max_speed_kmh: float = Field(default=900.0, ge=10.0, le=10000.0, description="Maximum feasible speed threshold (km/h)")


class BaselineSeedRequest(BaseModel):
    count: int = Field(default=20, ge=1, le=1000, description="Number of baseline samples to seed")
    avg_bytes_out: float = Field(default=1000.0, ge=0.0)
    avg_flow_duration_ms: float = Field(default=100.0, ge=0.0)
    primary_hours: List[int] = Field(default=[9, 10, 11, 12, 13, 14, 15, 16, 17], description="Business hours to populate")


@router.get("/status")
async def get_ueba_status() -> Dict[str, Any]:
    """Returns UEBA engine state, active entity counts, and anomaly metrics."""
    return ueba_engine.get_status()


@router.post("/evaluate")
async def evaluate_behavior(req: UEBAEvaluateRequest) -> Dict[str, Any]:
    """Evaluates an event payload against dynamic user and entity behavioral baselines."""
    try:
        event_dict = req.model_dump()
        result = ueba_engine.evaluate_event(event_dict)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"UEBA evaluation error: {str(e)}",
        )


@router.get("/baselines/{entity_type}/{entity_id}")
async def get_entity_baseline(entity_type: str, entity_id: str) -> Dict[str, Any]:
    """Retrieves current behavioral profile and rolling statistics for a user or host."""
    if entity_type.lower() not in ["user", "host", "ip"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid entity_type: '{entity_type}'. Must be 'user', 'host', or 'ip'.",
        )

    baseline = baseline_store.get(entity_type, entity_id)
    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baseline profile found for {entity_type} '{entity_id}'.",
        )
    return baseline.to_dict()


@router.post("/baselines/{entity_type}/{entity_id}/seed")
async def seed_entity_baseline(entity_type: str, entity_id: str, req: BaselineSeedRequest) -> Dict[str, Any]:
    """Seeds a baseline profile with historical data for demonstration or testing."""
    if entity_type.lower() not in ["user", "host", "ip"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid entity_type: '{entity_type}'. Must be 'user', 'host', or 'ip'.",
        )

    baseline = baseline_store.get_or_create(entity_type, entity_id)
    for i in range(req.count):
        hour = req.primary_hours[i % len(req.primary_hours)]
        sim_ts = datetime(2026, 9, 1, hour, 0, 0, tzinfo=timezone.utc)
        baseline.update(
            features={
                "bytes_out": req.avg_bytes_out + (i * 10.0),
                "bytes_out_ratio": 0.5,
                "flow_duration_ms": req.avg_flow_duration_ms,
                "failed_logins_window": 0.0,
            },
            timestamp=sim_ts,
            dst_port=443,
        )

    return {
        "status": "SEEDED",
        "entity_type": entity_type,
        "entity_id": entity_id,
        "total_events": baseline.total_events,
        "profile": baseline.to_dict(),
    }


@router.post("/impossible-travel")
async def evaluate_geo_travel(req: GeoTravelRequest) -> Dict[str, Any]:
    """Calculates Haversine distance and checks for impossible travel velocity."""
    try:
        p1 = GeoPoint(
            latitude=req.origin_lat,
            longitude=req.origin_lon,
            timestamp=datetime.fromisoformat(req.origin_timestamp),
            city=req.origin_city or "",
        )
        p2 = GeoPoint(
            latitude=req.dest_lat,
            longitude=req.dest_lon,
            timestamp=datetime.fromisoformat(req.dest_timestamp),
            city=req.dest_city or "",
        )
        return detect_impossible_travel(p1, p2, max_speed_kmh=req.max_speed_kmh)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error evaluating travel points: {str(e)}",
        )


@router.get("/anomalies")
async def get_recent_anomalies(limit: int = Query(default=50, ge=1, le=200)) -> List[Dict[str, Any]]:
    """Retrieves recent high-deviation behavioral anomalies."""
    return ueba_engine.get_anomalies(limit=limit)

