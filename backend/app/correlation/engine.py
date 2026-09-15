# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Sliding-Window Temporal Alert Correlation and Incident Engine."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set  # type: ignore

try:
    from ..database.session import AsyncSessionLocal  # type: ignore
    from ..streaming.topics import EventTopic  # type: ignore
    from ..api.websockets.manager import ws_manager  # type: ignore
    from ..models.incident import AttackStage, IncidentStatus  # type: ignore
    from ..models.alert import AlertSeverity  # type: ignore
    from .rules import CorrelationRules  # type: ignore
    from .incident_builder import IncidentBuilder  # type: ignore
except (ImportError, ValueError):
    from backend.app.database.session import AsyncSessionLocal  # type: ignore
    from backend.app.streaming.topics import EventTopic  # type: ignore
    from backend.app.api.websockets.manager import ws_manager  # type: ignore
    from backend.app.models.incident import AttackStage, IncidentStatus  # type: ignore
    from backend.app.models.alert import AlertSeverity  # type: ignore
    from backend.app.correlation.rules import CorrelationRules  # type: ignore
    from backend.app.correlation.incident_builder import IncidentBuilder  # type: ignore

logger = logging.getLogger("cyberdefense.correlation_engine")


class AlertCorrelationEngine:
    """Aggregates, contextualizes, and correlates streaming alerts into cohesive security incidents."""

    def __init__(self, window_seconds: int = 900, broker=None) -> None:
        self.window_seconds = window_seconds  # Default 15 minutes
        self._broker = broker
        # In-memory candidate index: incident_id -> candidate metadata
        self._candidates: Dict[str, Dict[str, Any]] = {}

    @property
    def broker(self):
        if self._broker is None:
            try:
                from ..streaming.broker import event_broker  # type: ignore
            except (ImportError, ValueError):
                from backend.app.streaming.broker import event_broker  # type: ignore
            self._broker = event_broker
        return self._broker

    def _cleanup_expired(self, current_ts: datetime) -> None:
        """Removes candidates outside the sliding temporal correlation window."""
        cutoff = current_ts - timedelta(seconds=self.window_seconds)
        expired_ids = [
            cid for cid, cand in self._candidates.items()
            if cand["last_seen"] < cutoff
        ]
        for cid in expired_ids:
            logger.debug("Purging expired candidate %s from active correlation window", cid)
            del self._candidates[cid]

    async def correlate_alert(
        self,
        alert_dict: Dict[str, Any],
        db_session=None,
    ) -> Dict[str, Any]:
        """Correlates an incoming security alert into an active incident or spawns a new one."""
        # 1. Parse timestamp
        ts_raw = alert_dict.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                alert_ts = datetime.fromisoformat(ts_raw)
            except Exception:
                alert_ts = datetime.now(timezone.utc)
        elif isinstance(ts_raw, datetime):
            alert_ts = ts_raw
        else:
            alert_ts = datetime.now(timezone.utc)

        # Ensure tz-aware
        if alert_ts.tzinfo is None:
            alert_ts = alert_ts.replace(tzinfo=timezone.utc)

        self._cleanup_expired(alert_ts)

        # 2. Extract alert attributes
        alert_attack_type = alert_dict.get("attack_type") or alert_dict.get("title")
        stage, tech_id, tactic = CorrelationRules.map_attack_stage(alert_attack_type)
        confidence = float(alert_dict.get("confidence", 0.7))
        anomaly_score = float(alert_dict.get("anomaly_score", 0.5))
        alert_id = alert_dict.get("id") or alert_dict.get("alert_id") or str(uuid.uuid4())

        alert_entities = {
            "source_ip": alert_dict.get("source_ip"),
            "destination_ip": alert_dict.get("destination_ip"),
            "user_id": alert_dict.get("user_id"),
            "asset_id": alert_dict.get("asset_id"),
        }

        # 3. Match against active candidates
        matched_candidate_id: Optional[str] = None
        match_reason: Optional[str] = None

        for cid, cand in self._candidates.items():
            # Check temporal window: alert within candidate's window
            window_diff = abs((alert_ts - cand["last_seen"]).total_seconds())
            if window_diff <= self.window_seconds:
                cand_entities = {
                    "source_ips": cand["source_ips"],
                    "destination_ips": cand["destination_ips"],
                    "user_ids": cand["user_ids"],
                    "asset_ids": cand["asset_ids"],
                }
                is_match, reason = CorrelationRules.match_entities(alert_entities, cand_entities)
                if is_match:
                    matched_candidate_id = cid
                    match_reason = reason
                    break

        # 4. Handle Existing Incident Match vs New Incident Spawn
        if matched_candidate_id:
            cand = self._candidates[matched_candidate_id]
            if alert_entities["source_ip"]:
                cand["source_ips"].add(alert_entities["source_ip"])
            if alert_entities["destination_ip"]:
                cand["destination_ips"].add(alert_entities["destination_ip"])
            if alert_entities["user_id"]:
                cand["user_ids"].add(alert_entities["user_id"])
            if alert_entities["asset_id"]:
                cand["asset_ids"].add(alert_entities["asset_id"])

            cand["confidences"].append(confidence)
            cand["anomaly_scores"].append(anomaly_score)
            cand["stages"].append(stage)
            cand["alert_ids"].append(alert_id)
            cand["last_seen"] = max(cand["last_seen"], alert_ts)

            updated_stage = CorrelationRules.evaluate_highest_stage(cand["stages"])
            updated_risk = CorrelationRules.calculate_composite_risk_score(
                cand["confidences"],
                cand["anomaly_scores"],
                updated_stage,
            )
            updated_sev = CorrelationRules.determine_severity(updated_risk)

            incident_record = None
            if db_session:
                incident_record = await IncidentBuilder.update_incident(
                    db=db_session,
                    incident_id=matched_candidate_id,
                    new_alert=alert_dict,
                    updated_stage=updated_stage,
                    updated_risk_score=updated_risk,
                    updated_severity=updated_sev,
                )
            else:
                try:
                    async with AsyncSessionLocal() as session:
                        incident_record = await IncidentBuilder.update_incident(
                            db=session,
                            incident_id=matched_candidate_id,
                            new_alert=alert_dict,
                            updated_stage=updated_stage,
                            updated_risk_score=updated_risk,
                            updated_severity=updated_sev,
                        )
                except Exception as e:
                    logger.warning("Failed to persist incident update to DB: %s", str(e))

            result = {
                "action": "CORRELATED_INTO_EXISTING",
                "incident_id": matched_candidate_id,
                "match_reason": match_reason,
                "attack_stage": updated_stage.value,
                "composite_risk_score": updated_risk,
                "severity": updated_sev.value,
                "correlated_alert_count": len(cand["alert_ids"]),
                "last_seen": cand["last_seen"].isoformat(),
            }

            # Broadcast escalation
            await ws_manager.broadcast({
                "type": "INCIDENT_ESCALATED",
                "data": result,
            })

        else:
            # Spawn new incident
            new_stage = stage
            new_risk = CorrelationRules.calculate_composite_risk_score(
                [confidence],
                [anomaly_score],
                new_stage,
            )
            new_sev = CorrelationRules.determine_severity(new_risk)

            new_incident_id = str(uuid.uuid4())
            if db_session:
                db_inc = await IncidentBuilder.create_incident(
                    db=db_session,
                    initial_alert=alert_dict,
                    attack_stage=new_stage,
                    risk_score=new_risk,
                    severity=new_sev,
                )
                if db_inc:
                    new_incident_id = db_inc.id
            else:
                try:
                    async with AsyncSessionLocal() as session:
                        db_inc = await IncidentBuilder.create_incident(
                            db=session,
                            initial_alert=alert_dict,
                            attack_stage=new_stage,
                            risk_score=new_risk,
                            severity=new_sev,
                        )
                        if db_inc:
                            new_incident_id = db_inc.id
                except Exception as e:
                    logger.warning("Failed to persist new incident to DB: %s", str(e))

            # Store in candidate index
            self._candidates[new_incident_id] = {
                "incident_id": new_incident_id,
                "start_time": alert_ts,
                "last_seen": alert_ts,
                "source_ips": {alert_entities["source_ip"]} if alert_entities["source_ip"] else set(),
                "destination_ips": {alert_entities["destination_ip"]} if alert_entities["destination_ip"] else set(),
                "user_ids": {alert_entities["user_id"]} if alert_entities["user_id"] else set(),
                "asset_ids": {alert_entities["asset_id"]} if alert_entities["asset_id"] else set(),
                "confidences": [confidence],
                "anomaly_scores": [anomaly_score],
                "stages": [new_stage],
                "alert_ids": [alert_id],
            }

            result = {
                "action": "CREATED_NEW_INCIDENT",
                "incident_id": new_incident_id,
                "attack_stage": new_stage.value,
                "composite_risk_score": new_risk,
                "severity": new_sev.value,
                "correlated_alert_count": 1,
                "start_time": alert_ts.isoformat(),
            }

            # Broadcast new incident
            await ws_manager.broadcast({
                "type": "NEW_SECURITY_INCIDENT",
                "data": result,
            })

        # 5. Emit to streaming topic
        try:
            await self.broker.publish(EventTopic.ALERTS_CORRELATED.value, result)
        except Exception as e:
            logger.warning("Could not publish to %s: %s", EventTopic.ALERTS_CORRELATED.value, str(e))

        return result

    async def correlate_batch(
        self,
        alerts: List[Dict[str, Any]],
        db_session=None,
    ) -> List[Dict[str, Any]]:
        """Batch correlates a sequence of alerts in chronological order."""
        def get_ts(a: Dict[str, Any]) -> datetime:
            t = a.get("timestamp")
            if isinstance(t, datetime):
                return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
            if isinstance(t, str):
                try:
                    dt = datetime.fromisoformat(t)
                    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except Exception:
                    pass
            return datetime.now(timezone.utc)

        sorted_alerts = sorted(alerts, key=get_ts)
        results = []
        for alert in sorted_alerts:
            res = await self.correlate_alert(alert, db_session=db_session)
            results.append(res)
        return results

    def reset_state(self) -> None:
        """Clears all in-memory correlation candidate tracking."""
        self._candidates.clear()


# Global correlation engine singleton
correlation_engine = AlertCorrelationEngine()
