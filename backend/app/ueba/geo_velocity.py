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
"""Geo-Velocity and Impossible Travel Detection using Haversine Great-Circle Math.

Detects account hijacking, concurrent credential compromise, or proxy hopping
when consecutive authentication attempts occur from locations separated by a distance
that cannot be traversed at commercial airline speeds (>900 km/h).
"""

import math
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass


EARTH_RADIUS_KM = 6371.0
MAX_COMMERCIAL_FLIGHT_SPEED_KMH = 900.0


@dataclass
class GeoPoint:
    """Represents a geographic location and observation timestamp."""

    latitude: float
    longitude: float
    timestamp: datetime
    ip: str = ""
    city: str = ""
    country: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GeoPoint":
        ts = data.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts)
            except Exception:
                dt = datetime.now(timezone.utc)
        elif isinstance(ts, datetime):
            dt = ts
        else:
            dt = datetime.now(timezone.utc)

        return cls(
            latitude=float(data.get("latitude", 0.0)),
            longitude=float(data.get("longitude", 0.0)),
            timestamp=dt,
            ip=str(data.get("ip", "")),
            city=str(data.get("city", "")),
            country=str(data.get("country", "")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timestamp": self.timestamp.isoformat(),
            "ip": self.ip,
            "city": self.city,
            "country": self.country,
        }


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two decimal degree coordinates in kilometers."""
    # Convert degrees to radians
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    # Haversine formula: a = sin²(Δφ/2) + cos φ1 ⋅ cos φ2 ⋅ sin²(Δλ/2)
    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    # Clip to [0, 1] to avoid float precision domain errors in asin
    a = min(1.0, max(0.0, a))
    c = 2.0 * math.asin(math.sqrt(a))
    return round(EARTH_RADIUS_KM * c, 2)


def calculate_velocity_kmh(distance_km: float, time_delta_seconds: float) -> float:
    """Calculates apparent speed in kilometers per hour."""
    time_hours = max(time_delta_seconds, 1.0) / 3600.0
    return round(distance_km / time_hours, 2)


def detect_impossible_travel(
    p1: GeoPoint,
    p2: GeoPoint,
    max_speed_kmh: float = MAX_COMMERCIAL_FLIGHT_SPEED_KMH,
    min_distance_threshold_km: float = 100.0,
) -> Dict[str, Any]:
    """Evaluates two consecutive location points for physically impossible travel.

    Guards against false positives:
    - If distance is below min_distance_threshold_km (e.g. adjacent cellular towers or ISP DHCP switches),
      impossible travel is suppressed even if elapsed time is small.
    """
    distance_km = haversine_distance_km(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

    # Compute absolute elapsed time in seconds
    t1 = p1.timestamp.timestamp()
    t2 = p2.timestamp.timestamp()
    elapsed_seconds = abs(t2 - t1)

    speed_kmh = calculate_velocity_kmh(distance_km, elapsed_seconds)

    # Impossible travel triggered if speed exceeds flight limit and distance is non-trivial
    is_impossible = distance_km >= min_distance_threshold_km and speed_kmh > max_speed_kmh

    severity = "INFO"
    if is_impossible:
        if speed_kmh > 3000.0:
            severity = "CRITICAL"
        else:
            severity = "HIGH"

    desc = (
        f"Impossible travel detected: {distance_km} km traversed in {int(elapsed_seconds)}s "
        f"({speed_kmh} km/h > threshold {max_speed_kmh} km/h) between {p1.city or p1.ip} and {p2.city or p2.ip}."
        if is_impossible
        else f"Feasible travel velocity ({speed_kmh} km/h across {distance_km} km)."
    )

    return {
        "is_impossible": is_impossible,
        "distance_km": distance_km,
        "elapsed_seconds": round(elapsed_seconds, 1),
        "speed_kmh": speed_kmh,
        "threshold_kmh": max_speed_kmh,
        "severity": severity,
        "description": desc,
        "origin": p1.to_dict(),
        "destination": p2.to_dict(),
    }

