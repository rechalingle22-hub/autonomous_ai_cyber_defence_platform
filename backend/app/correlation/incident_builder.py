# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Incident and Attack Timeline Builder and Database Synthesizer."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List  # type: ignore
from sqlalchemy import select  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

try:
    from ..models.incident import Incident, AttackTimeline, IncidentStatus, AttackStage  # type: ignore
    from ..models.alert import Alert, AlertSeverity  # type: ignore
    from .rules import CorrelationRules  # type: ignore
except (ImportError, ValueError):
    from backend.app.models.incident import Incident, AttackTimeline, IncidentStatus, AttackStage  # type: ignore
    from backend.app.models.alert import Alert, AlertSeverity  # type: ignore
    from backend.app.correlation.rules import CorrelationRules  # type: ignore

logger = logging.getLogger("cyberdefense.incident_builder")


class IncidentBuilder:
    """Builds and updates persistent Incident records and chronological AttackTimeline entries."""

    @staticmethod
    async def create_incident(
        db: AsyncSession,
        initial_alert: Dict[str, Any],
        attack_stage: AttackStage,
        risk_score: float,
        severity: AlertSeverity,
    ) -> Incident:
        """Creates a new persistent Incident record and its initial timeline step."""
        entity_label = (
            initial_alert.get("destination_ip")
            or initial_alert.get("source_ip")
            or initial_alert.get("user_id")
            or "Enterprise Network"
        )
        alert_title = initial_alert.get("title") or initial_alert.get("attack_type") or "Suspicious Activity"
        
        ts_raw = initial_alert.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                alert_ts = datetime.fromisoformat(ts_raw)
            except Exception:
                alert_ts = datetime.now(timezone.utc)
        elif isinstance(ts_raw, datetime):
            alert_ts = ts_raw
        else:
            alert_ts = datetime.now(timezone.utc)

        incident_id = str(uuid.uuid4())
        incident = Incident(
            id=incident_id,
            title=f"Incident: {attack_stage.value} ({alert_title}) targeting {entity_label}",
            description=initial_alert.get("description") or f"Correlated security alert cluster targeting {entity_label}.",
            severity=severity,
            composite_risk_score=risk_score,
            status=IncidentStatus.OPEN,
            attack_stage=attack_stage,
            primary_asset_id=initial_alert.get("asset_id"),
            start_time=alert_ts,
            end_time=alert_ts,
            created_at=datetime.now(timezone.utc),
        )
        db.add(incident)
        await db.flush()

        # Create first timeline entry
        await IncidentBuilder.add_timeline_step(db, incident.id, initial_alert)

        # Link alert to incident if alert_id is present
        await IncidentBuilder.link_alert(db, incident.id, initial_alert)

        await db.commit()
        await db.refresh(incident)
        logger.info("Created new Incident %s (Stage=%s, Risk=%.1f)", incident.id, attack_stage.value, risk_score)
        return incident

    @staticmethod
    async def update_incident(
        db: AsyncSession,
        incident_id: str,
        new_alert: Dict[str, Any],
        updated_stage: AttackStage,
        updated_risk_score: float,
        updated_severity: AlertSeverity,
    ) -> Optional[Incident]:
        """Updates an existing Incident with an additional alert, escalated stage, and new timeline step."""
        res = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = res.scalar_one_or_none()
        if not incident:
            logger.warning("Incident %s not found for update", incident_id)
            return None

        ts_raw = new_alert.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                alert_ts = datetime.fromisoformat(ts_raw)
            except Exception:
                alert_ts = datetime.now(timezone.utc)
        elif isinstance(ts_raw, datetime):
            alert_ts = ts_raw
        else:
            alert_ts = datetime.now(timezone.utc)

        # Update fields
        incident.composite_risk_score = updated_risk_score
        incident.severity = updated_severity
        
        # If new stage is higher in progression, escalate stage and refresh title
        if CorrelationRules.get_stage_weight(updated_stage) >= CorrelationRules.get_stage_weight(incident.attack_stage):
            incident.attack_stage = updated_stage
            new_title_part = new_alert.get("attack_type") or new_alert.get("title") or "Escalation"
            entity_label = (
                new_alert.get("destination_ip")
                or new_alert.get("source_ip")
                or "Target"
            )
            incident.title = f"Escalated Incident: {updated_stage.value} ({new_title_part}) on {entity_label}"

        if alert_ts > incident.end_time:
            incident.end_time = alert_ts

        # Append timeline entry
        await IncidentBuilder.add_timeline_step(db, incident.id, new_alert)

        # Link alert
        await IncidentBuilder.link_alert(db, incident.id, new_alert)

        await db.commit()
        await db.refresh(incident)
        logger.info("Updated Incident %s (Stage=%s, Risk=%.1f)", incident.id, incident.attack_stage.value, updated_risk_score)
        return incident

    @staticmethod
    async def add_timeline_step(
        db: AsyncSession,
        incident_id: str,
        alert_dict: Dict[str, Any],
    ) -> AttackTimeline:
        """Appends an attack timeline entry for the given alert."""
        ts_raw = alert_dict.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw)
            except Exception:
                ts = datetime.now(timezone.utc)
        elif isinstance(ts_raw, datetime):
            ts = ts_raw
        else:
            ts = datetime.now(timezone.utc)

        src = alert_dict.get("source_ip", "unknown")
        dst = alert_dict.get("destination_ip", "unknown")
        entity_repr = f"{src} -> {dst}"
        if alert_dict.get("user_id"):
            entity_repr += f" (User: {alert_dict.get('user_id')})"

        det_source = alert_dict.get("detection_source") or "XGBOOST"
        if hasattr(det_source, "value"):
            det_source = det_source.value
        elif not isinstance(det_source, str):
            det_source = str(det_source)

        alert_sev = alert_dict.get("severity") or AlertSeverity.MEDIUM
        if isinstance(alert_sev, str):
            alert_sev = getattr(AlertSeverity, alert_sev.upper(), AlertSeverity.MEDIUM)

        _, tech_id, _ = CorrelationRules.map_attack_stage(
            alert_dict.get("attack_type") or alert_dict.get("title")
        )

        title = alert_dict.get("title") or alert_dict.get("attack_type") or "Security Alert"
        summary = f"[{det_source}] {title} (Conf: {alert_dict.get('confidence', 0.0):.2f}, Anom: {alert_dict.get('anomaly_score', 0.0):.2f})"

        timeline = AttackTimeline(
            id=str(uuid.uuid4()),
            incident_id=incident_id,
            timestamp=ts,
            event_summary=summary[:512],
            entity=entity_repr[:128],
            detection_source=str(det_source)[:64],
            mitre_technique=str(tech_id)[:64],
            severity=alert_sev,
        )
        db.add(timeline)
        await db.flush()
        return timeline

    @staticmethod
    async def link_alert(
        db: AsyncSession,
        incident_id: str,
        alert_dict: Dict[str, Any],
    ) -> None:
        """Associates the Alert ORM row with the incident_id if present in DB."""
        alert_id = alert_dict.get("id") or alert_dict.get("alert_id")
        if not alert_id:
            return

        res = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert_obj = res.scalar_one_or_none()
        if alert_obj:
            alert_obj.incident_id = incident_id
            await db.flush()

