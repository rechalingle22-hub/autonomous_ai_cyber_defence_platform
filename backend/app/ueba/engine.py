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
"""UEBA (User and Entity Behavior Analytics) Detection Engine.

Fuses:
1. Online Statistical Z-Score Deviations (Volume, Rate, Auth velocity).
2. Time-of-Day / Out-of-Hours Historical Probability Scoring.
3. Shannon Destination Port Entropy (Scanning & Lateral Movement).
4. Geo-Velocity Impossible Travel Detection.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from .baseline import BaselineStore, baseline_store, EntityBaseline
from .geo_velocity import GeoPoint, detect_impossible_travel




logger = logging.getLogger("cyberdefense.ueba")


class UEBAEngine:
    """Core analytics engine for detecting anomalous user and host behaviors."""

    def __init__(self, store: Optional[BaselineStore] = None) -> None:
        self.store: BaselineStore = store or baseline_store
        self.recent_anomalies: List[Dict[str, Any]] = []
        self._max_anomaly_log: int = 200

    def evaluate_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates an incoming event dictionary against historical baselines.

        Returns structured UEBA anomaly metrics and updates entity profiles.
        """
        user_id = event_data.get("user_id")
        source_ip = event_data.get("source_ip")
        features = event_data.get("features", {})
        metadata = event_data.get("metadata", {})
        raw_ts = event_data.get("timestamp")

        if isinstance(raw_ts, str):
            try:
                event_time = datetime.fromisoformat(raw_ts)
            except Exception:
                event_time = datetime.now(timezone.utc)
        elif isinstance(raw_ts, datetime):
            event_time = raw_ts
        else:
            event_time = datetime.now(timezone.utc)

        dst_port = event_data.get("destination_port") or features.get("destination_port")
        if dst_port is not None:
            try:
                dst_port = int(dst_port)
            except (ValueError, TypeError):
                dst_port = None

        flags: List[str] = []
        z_scores: Dict[str, float] = {}
        anomaly_score = 0.0
        details: Dict[str, Any] = {}

        # 1. Evaluate User Baseline (if user_id present)
        user_baseline = None
        if user_id:
            user_baseline = self.store.get_or_create("user", str(user_id))
            user_eval = self._evaluate_entity_baseline(user_baseline, features, event_time)
            flags.extend(user_eval["flags"])
            z_scores.update(user_eval["z_scores"])
            anomaly_score = max(anomaly_score, user_eval["anomaly_score"])

            # Evaluate Impossible Travel if geo location metadata is provided
            geo_info = metadata.get("geo") or event_data.get("geo")
            if geo_info and "latitude" in geo_info and "longitude" in geo_info:
                curr_point = GeoPoint.from_dict({**geo_info, "timestamp": event_time, "ip": source_ip or ""})
                if user_baseline.recent_locations:
                    prev_point = GeoPoint.from_dict(user_baseline.recent_locations[-1])
                    travel_res = detect_impossible_travel(prev_point, curr_point)
                    if travel_res["is_impossible"]:
                        flags.append("IMPOSSIBLE_TRAVEL")
                        anomaly_score = max(anomaly_score, 0.90)
                        details["impossible_travel"] = travel_res

        # 2. Evaluate Host / IP Baseline
        host_baseline = None
        if source_ip and source_ip != "127.0.0.1":
            host_baseline = self.store.get_or_create("host", str(source_ip))
            host_eval = self._evaluate_entity_baseline(host_baseline, features, event_time)
            for f in host_eval["flags"]:
                if f not in flags:
                    flags.append(f)
            z_scores.update(host_eval["z_scores"])
            anomaly_score = max(anomaly_score, host_eval["anomaly_score"])

            # Evaluate Port Entropy Anomaly
            if dst_port is not None and dst_port > 0:
                current_entropy = host_baseline.calculate_shannon_entropy()
                if current_entropy > 3.0 and len(host_baseline.destination_ports) > 15:
                    if "PORT_SCAN_BEHAVIOR" not in flags:
                        flags.append("PORT_SCAN_BEHAVIOR")
                        anomaly_score = max(anomaly_score, 0.70)
                        details["port_entropy"] = current_entropy

        # 3. Derive Severity from Anomaly Score
        is_anomaly = anomaly_score >= 0.60 or len(flags) > 0
        if anomaly_score >= 0.85:
            severity = "CRITICAL"
        elif anomaly_score >= 0.65:
            severity = "HIGH"
        elif anomaly_score >= 0.45:
            severity = "MEDIUM"
        elif anomaly_score >= 0.25:
            severity = "LOW"
        else:
            severity = "INFO"

        result = {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(min(1.0, anomaly_score), 4),
            "severity": severity,
            "flags": flags,
            "z_scores": z_scores,
            "evaluated_user": user_id,
            "evaluated_host": source_ip,
            "timestamp": event_time.isoformat(),
            "details": details,
        }

        # 4. Record anomaly in recent buffer
        if is_anomaly:
            self.recent_anomalies.append({**result, "event_id": event_data.get("event_id")})
            if len(self.recent_anomalies) > self._max_anomaly_log:
                self.recent_anomalies.pop(0)

        # 5. Update baselines with current observation
        geo_info = metadata.get("geo") or event_data.get("geo")
        if user_baseline:
            user_baseline.update(features, timestamp=event_time, dst_port=dst_port, geo_location=geo_info)
        if host_baseline:
            host_baseline.update(features, timestamp=event_time, dst_port=dst_port, geo_location=geo_info)

        return result

    def _evaluate_entity_baseline(
        self,
        baseline: EntityBaseline,
        features: Dict[str, Any],
        event_time: datetime,
    ) -> Dict[str, Any]:
        """Calculates Z-Scores and temporal probability against an entity's profile."""
        flags = []
        z_scores = {}
        score = 0.0

        # Need minimum 5 baseline events for statistical significance
        has_baseline = baseline.total_events >= 5

        # Check Failed Logins Spike
        if "failed_logins_window" in features:
            val = float(features["failed_logins_window"])
            if has_baseline:
                z = baseline.metrics["failed_logins_window"].z_score(val, min_std=1.0)
                z_scores[f"{baseline.entity_type}_failed_logins_z"] = round(z, 2)
                if z >= 3.0 and val >= 5.0:
                    flags.append("FAILED_LOGINS_SPIKE")
                    score = max(score, min(0.85, 0.5 + (z * 0.05)))
            elif val >= 10.0:
                flags.append("FAILED_LOGINS_SPIKE")
                score = max(score, 0.75)

        # Check Outbound Data Volume Spike
        if "bytes_out_ratio" in features:
            val = float(features["bytes_out_ratio"])
            if has_baseline:
                z = baseline.metrics["bytes_out"].z_score(val, min_std=0.1)
                z_scores[f"{baseline.entity_type}_bytes_out_z"] = round(z, 2)
                if z >= 3.0:
                    flags.append("VOLUME_SPIKE")
                    score = max(score, min(0.80, 0.4 + (z * 0.05)))

        # Check Off-Hours Activity (if baseline has sufficient hourly distribution)
        if baseline.total_events >= 20:
            hour_prob = baseline.get_hour_probability(event_time.hour)
            if hour_prob < 0.02:  # Less than 2% of previous events happened at this hour
                flags.append("OFF_HOURS_ACCESS")
                score = max(score, 0.65)

        return {
            "flags": flags,
            "z_scores": z_scores,
            "anomaly_score": score,
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns UEBA engine state and baseline summary."""
        counts = self.store.count()
        return {
            "status": "OPERATIONAL",
            "tracked_users": counts["users"],
            "tracked_hosts": counts["hosts"],
            "total_entities": counts["total"],
            "recent_anomalies_count": len(self.recent_anomalies),
        }

    def get_anomalies(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent UEBA detected behavioral anomalies."""
        return list(reversed(self.recent_anomalies[-limit:]))


# Global UEBA engine instance
ueba_engine = UEBAEngine()

