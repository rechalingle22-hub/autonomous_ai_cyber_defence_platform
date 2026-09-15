"""Standard topic definitions and DLQ constants for real-time security event streaming."""

from enum import Enum


class EventTopic(str, Enum):
    """Standard Kafka / In-Memory streaming topics for defensive SOC pipeline."""

    TELEMETRY_RAW = "telemetry.raw"
    TELEMETRY_NORMALIZED = "telemetry.normalized"
    ALERTS_DETECTED = "alerts.detected"
    ALERTS_CORRELATED = "alerts.correlated"
    ALERTS_DLQ = "alerts.dlq"


ALL_TOPICS = [t.value for t in EventTopic]

