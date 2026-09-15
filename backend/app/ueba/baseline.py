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
"""Entity Behavioral Baselines using Welford's Algorithm for Online Statistics.

Maintains running mean, variance, standard deviation, hourly access histograms,
and port distributions without storing full unbounded historical events.
"""

import math
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class MetricStats:
    """Online single-pass statistical tracker using Welford's algorithm."""

    def __init__(
        self,
        count: int = 0,
        mean: float = 0.0,
        m2: float = 0.0,
        min_val: float = float("inf"),
        max_val: float = float("-inf"),
    ) -> None:
        self.count: int = count
        self.mean: float = mean
        self.m2: float = m2
        self.min_val: float = min_val if count > 0 else 0.0
        self.max_val: float = max_val if count > 0 else 0.0

    @property
    def variance(self) -> float:
        """Sample variance: M2 / (n - 1) for n > 1, else 0.0."""
        if self.count > 1:
            return max(0.0, self.m2 / (self.count - 1))
        return 0.0

    @property
    def std_dev(self) -> float:
        """Standard deviation: sqrt(variance)."""
        return math.sqrt(self.variance)

    def update(self, val: float) -> None:
        """Incorporates a new observation using Welford's algorithm."""
        val = float(val)
        self.count += 1
        delta = val - self.mean
        self.mean += delta / self.count
        delta2 = val - self.mean
        self.m2 += delta * delta2

        if self.count == 1:
            self.min_val = val
            self.max_val = val
        else:
            self.min_val = min(self.min_val, val)
            self.max_val = max(self.max_val, val)

    def z_score(self, val: float, min_std: float = 1.0) -> float:
        """Calculates standard score (Z-Score) with floor protection against zero variance."""
        effective_std = max(self.std_dev, min_std)
        return (float(val) - self.mean) / effective_std

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "mean": round(self.mean, 4),
            "variance": round(self.variance, 4),
            "std_dev": round(self.std_dev, 4),
            "min": round(self.min_val, 4) if self.count > 0 else 0.0,
            "max": round(self.max_val, 4) if self.count > 0 else 0.0,
        }


class EntityBaseline:
    """Behavioral profile for a specific network entity (User, Host, IP, or Service)."""

    def __init__(self, entity_type: str, entity_id: str) -> None:
        self.entity_type: str = entity_type.lower()
        self.entity_id: str = entity_id
        self.created_at: datetime = datetime.now(timezone.utc)
        self.last_seen: datetime = self.created_at
        self.total_events: int = 0

        # Numerical metric trackers
        self.metrics: Dict[str, MetricStats] = {
            "bytes_out": MetricStats(),
            "bytes_in": MetricStats(),
            "flow_bytes_per_sec": MetricStats(),
            "flow_duration_ms": MetricStats(),
            "failed_logins_window": MetricStats(),
            "port_entropy": MetricStats(),
        }

        # 24-hour histogram of event activity (UTC hours 0..23)
        self.hourly_activity: List[int] = [0] * 24

        # Destination port access frequencies (for Shannon entropy tracking)
        self.destination_ports: Dict[int, int] = {}

        # Recent observed geographic locations (sliding buffer of up to 10)
        self.recent_locations: List[Dict[str, Any]] = []

    def update(
        self,
        features: Dict[str, Any],
        timestamp: Optional[datetime] = None,
        dst_port: Optional[int] = None,
        geo_location: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Updates baseline with observation data."""
        self.total_events += 1
        ts = timestamp or datetime.now(timezone.utc)
        self.last_seen = ts

        # 1. Update hourly distribution
        hour = ts.hour
        self.hourly_activity[hour] += 1

        # 2. Update numerical metrics
        for metric_name, tracker in self.metrics.items():
            if metric_name in features and features[metric_name] is not None:
                try:
                    val = float(features[metric_name])
                    tracker.update(val)
                except (ValueError, TypeError):
                    pass

        # 3. Update destination port frequency
        if dst_port is not None and dst_port > 0:
            self.destination_ports[dst_port] = self.destination_ports.get(dst_port, 0) + 1

        # 4. Update geographic location history
        if geo_location and "latitude" in geo_location and "longitude" in geo_location:
            loc_record = {
                "latitude": float(geo_location["latitude"]),
                "longitude": float(geo_location["longitude"]),
                "city": geo_location.get("city", "Unknown"),
                "country": geo_location.get("country", "Unknown"),
                "ip": geo_location.get("ip", ""),
                "timestamp": ts.isoformat(),
            }
            self.recent_locations.append(loc_record)
            if len(self.recent_locations) > 10:
                self.recent_locations.pop(0)

    def calculate_shannon_entropy(self) -> float:
        """Calculates Shannon entropy of accessed destination ports: H = -sum(p * log2(p))."""
        if not self.destination_ports:
            return 0.0
        total_port_hits = sum(self.destination_ports.values())
        if total_port_hits <= 0:
            return 0.0

        entropy = 0.0
        for count in self.destination_ports.values():
            p = count / total_port_hits
            if p > 0.0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def get_hour_probability(self, hour: int) -> float:
        """Returns historical probability of activity during the given hour."""
        if self.total_events <= 0:
            return 1.0 / 24.0
        return self.hourly_activity[hour % 24] / self.total_events

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "created_at": self.created_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "total_events": self.total_events,
            "metrics": {k: v.to_dict() for k, v in self.metrics.items()},
            "hourly_distribution": self.hourly_activity,
            "distinct_ports_contacted": len(self.destination_ports),
            "port_shannon_entropy": self.calculate_shannon_entropy(),
            "recent_locations_count": len(self.recent_locations),
            "latest_location": self.recent_locations[-1] if self.recent_locations else None,
        }


class BaselineStore:
    """Thread-safe in-memory store for entity behavioral baselines."""

    def __init__(self) -> None:
        # Key: (entity_type, entity_id)
        self._store: Dict[tuple, EntityBaseline] = {}

    def get_or_create(self, entity_type: str, entity_id: str) -> EntityBaseline:
        key = (entity_type.lower(), str(entity_id))
        if key not in self._store:
            self._store[key] = EntityBaseline(entity_type=entity_type, entity_id=str(entity_id))
        return self._store[key]

    def get(self, entity_type: str, entity_id: str) -> Optional[EntityBaseline]:
        key = (entity_type.lower(), str(entity_id))
        return self._store.get(key)

    def list_entities(self, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        results = []
        for (etype, eid), baseline in self._store.items():
            if entity_type is None or etype == entity_type.lower():
                results.append(baseline.to_dict())
        return results

    def count(self) -> Dict[str, int]:
        user_count = sum(1 for (etype, _) in self._store.keys() if etype == "user")
        host_count = sum(1 for (etype, _) in self._store.keys() if etype == "host")
        return {"users": user_count, "hosts": host_count, "total": len(self._store)}

    def clear(self) -> None:
        self._store.clear()


# Global baseline store
baseline_store = BaselineStore()

