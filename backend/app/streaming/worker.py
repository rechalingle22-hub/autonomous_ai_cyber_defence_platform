"""Real-time Stream Processing Worker for Security Telemetry.

Processes telemetry streams through:
1. Raw Validation & Normalization (Raw -> Normalized or DLQ)
2. ML Hybrid Threat Detection & Classification (Normalized -> Detected Alerts)
3. Real-Time SOC WebSocket Alert Dispatch
"""

import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import ValidationError

from backend.app.streaming.topics import EventTopic
from backend.app.streaming.broker import event_broker
from backend.app.schemas.common_event import CommonEventSchema
from backend.app.detection.inference_engine import inference_engine
from backend.app.ueba.engine import ueba_engine
from backend.app.api.websockets.manager import ws_manager
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.alert import Alert, AlertSeverity, AlertStatus, DetectionSource

logger = logging.getLogger("cyberdefense.stream_worker")


class StreamDetectionWorker:
    """Consumes telemetry topics, executes AI detection, and generates real-time alerts."""

    def __init__(self, broker=None) -> None:
        self.broker = broker or event_broker
        self.is_registered: bool = False

    def register_handlers(self) -> None:
        """Subscribes handler callbacks to respective stream topics."""
        if self.is_registered:
            return
        self.broker.subscribe(EventTopic.TELEMETRY_RAW.value, self.handle_raw_telemetry)
        self.broker.subscribe(EventTopic.TELEMETRY_NORMALIZED.value, self.handle_normalized_telemetry)
        self.is_registered = True
        logger.info("StreamDetectionWorker handlers registered on broker: %s", type(self.broker).__name__)

    async def handle_raw_telemetry(self, raw_message: Dict[str, Any]) -> None:
        """Validates incoming raw telemetry and forwards to normalized topic or DLQ."""
        try:
            # Validate through CommonEventSchema
            event = CommonEventSchema(**raw_message)
            # Push normalized event to processing pipeline
            await self.broker.publish(EventTopic.TELEMETRY_NORMALIZED.value, event.model_dump())
        except ValidationError as ve:
            logger.warning("Malformed raw telemetry routed to DLQ: %s", str(ve))
            dlq_entry = {
                "failed_topic": EventTopic.TELEMETRY_RAW.value,
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "error_detail": str(ve),
                "validation_errors": json.loads(ve.json()),
                "raw_payload": raw_message,
            }
            await self.broker.publish(EventTopic.ALERTS_DLQ.value, dlq_entry)
        except Exception as e:
            logger.error("Unexpected error normalizing telemetry: %s", str(e))
            dlq_entry = {
                "failed_topic": EventTopic.TELEMETRY_RAW.value,
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "error_detail": str(e),
                "raw_payload": raw_message,
            }
            await self.broker.publish(EventTopic.ALERTS_DLQ.value, dlq_entry)

    async def handle_normalized_telemetry(self, event_data: Dict[str, Any]) -> None:
        """Executes hybrid ML inference and UEBA profiling on normalized event and generates alert if threat detected."""
        try:
            # 1. Hybrid ML Inference
            analysis = inference_engine.analyze_event(event_data)

            # 2. UEBA Behavioral Evaluation
            ueba_res = ueba_engine.evaluate_event(event_data)

            # 3. Check if threat detected by ML or UEBA
            ml_anomaly = (
                analysis.get("prediction") == "suspicious"
                or analysis.get("anomaly_score", 0.0) >= 0.65
                or analysis.get("attack_type", "BENIGN") != "BENIGN"
            )
            ueba_anomaly = ueba_res.get("is_anomaly", False)
            is_suspicious = ml_anomaly or ueba_anomaly

            if is_suspicious:
                raw_eid = event_data.get("event_id") or "anon"
                attack_type = analysis.get("attack_type", "ANOMALOUS_OTHER")
                if attack_type == "BENIGN" and ueba_anomaly:
                    flags_str = "_".join(ueba_res.get("flags", ["BEHAVIORAL_ANOMALY"]))
                    attack_type = flags_str[:32]

                effective_sev = analysis.get("severity", "MEDIUM")
                if ueba_res.get("severity") in ["HIGH", "CRITICAL"] and effective_sev in ["INFO", "LOW", "MEDIUM"]:
                    effective_sev = ueba_res.get("severity")

                effective_anomaly_score = max(
                    float(analysis.get("anomaly_score", 0.0)),
                    float(ueba_res.get("anomaly_score", 0.0)),
                )

                alert_payload = {
                    "alert_id": f"ALT-{str(raw_eid)[:8]}",
                    "title": f"Detected {attack_type} Activity",
                    "description": analysis.get("xai_explanation", {}).get(
                        "deterministic_summary",
                        f"Anomalous telemetry detected from {event_data.get('source_ip')}."
                    ),
                    "attack_type": attack_type,
                    "severity": effective_sev,
                    "confidence": max(float(analysis.get("confidence", 0.5)), 0.6 if ueba_anomaly else 0.5),
                    "anomaly_score": effective_anomaly_score,
                    "source_ip": event_data.get("source_ip"),
                    "destination_ip": event_data.get("destination_ip"),
                    "destination_port": event_data.get("destination_port"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "xai_explanation": analysis.get("xai_explanation", {}),
                    "detectors": analysis.get("detectors", {}),
                    "ueba": ueba_res,
                }

                # 4. Enrich alert with Cyber Threat Intelligence (CTI, CVE, MITRE)
                try:
                    from backend.app.threat_intel.enrichment_service import threat_enrichment_service
                    alert_payload = await threat_enrichment_service.enrich_alert(alert_payload)
                except Exception as tie:
                    logger.debug("Threat intelligence enrichment skipped: %s", str(tie))

                # 5. Publish to alerts.detected topic
                await self.broker.publish(EventTopic.ALERTS_DETECTED.value, alert_payload)

                # 6. Broadcast live alert over WebSocket to connected SOC analysts
                await ws_manager.broadcast({
                    "type": "SECURITY_ALERT",
                    "alert": alert_payload,
                })

                # 7. Persist alert to database asynchronously if session is available
                await self._persist_alert(alert_payload)

        except Exception as e:
            logger.error("Inference execution error in stream worker: %s", str(e), exc_info=True)
            dlq_entry = {
                "failed_topic": EventTopic.TELEMETRY_NORMALIZED.value,
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "error_detail": str(e),
                "event_data": event_data,
            }
            await self.broker.publish(EventTopic.ALERTS_DLQ.value, dlq_entry)

    async def _persist_alert(self, alert_dict: Dict[str, Any]) -> None:
        """Persists alert record into database."""
        """Persists alert record into database and triggers incident correlation."""
        try:
            async with AsyncSessionLocal() as session:
                severity_str = alert_dict.get("severity", "MEDIUM").upper()
                mapped_sev = getattr(AlertSeverity, severity_str, AlertSeverity.MEDIUM)

                alert = Alert(
                    title=alert_dict["title"],
                    description=alert_dict.get("description"),
                    detection_source=DetectionSource.XGBOOST,
                    severity=mapped_sev,
                    status=AlertStatus.NEW,
                    confidence=float(alert_dict.get("confidence", 0.5)),
                    anomaly_score=float(alert_dict.get("anomaly_score", 0.0)),
                    contributing_features=alert_dict.get("xai_explanation", {}),
                )
                session.add(alert)
                await session.commit()
                await session.refresh(alert)

                alert_payload = dict(alert_dict)
                alert_payload["id"] = alert.id
                from backend.app.correlation.engine import correlation_engine
                await correlation_engine.correlate_alert(alert_payload, db_session=session)
        except Exception as e:
            logger.warning("Could not persist stream alert to DB (non-fatal): %s", str(e))
            logger.warning("Could not persist or correlate stream alert (non-fatal): %s", str(e))


# Global worker instance
stream_worker = StreamDetectionWorker()
