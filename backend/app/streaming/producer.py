"""Stream Producer helper for pushing events and alerts to broker topics."""

from typing import Dict, Any, List, Union
from backend.app.streaming.broker import event_broker
from backend.app.streaming.topics import EventTopic
from backend.app.schemas.common_event import CommonEventSchema


class StreamProducer:
    """High-level producer client for streaming security telemetry."""

    def __init__(self, broker=event_broker) -> None:
        self.broker = broker

    async def send_raw_telemetry(self, raw_data: Dict[str, Any]) -> None:
        """Publishes raw telemetry dictionary for normalization and validation."""
        await self.broker.publish(EventTopic.TELEMETRY_RAW.value, raw_data)

    async def send_normalized_event(self, event: Union[CommonEventSchema, Dict[str, Any]]) -> None:
        """Publishes validated normalized CommonEventSchema event directly to ML inference queue."""
        payload = event.model_dump() if isinstance(event, CommonEventSchema) else event
        await self.broker.publish(EventTopic.TELEMETRY_NORMALIZED.value, payload)

    async def send_batch_telemetry(self, events: List[Union[CommonEventSchema, Dict[str, Any]]]) -> int:
        """Publishes a batch of events onto the normalized telemetry stream."""
        for ev in events:
            await self.send_normalized_event(ev)
        return len(events)

    async def send_alert(self, alert_data: Dict[str, Any]) -> None:
        """Publishes an alert directly to the detected alerts topic."""
        await self.broker.publish(EventTopic.ALERTS_DETECTED.value, alert_data)


stream_producer = StreamProducer()

