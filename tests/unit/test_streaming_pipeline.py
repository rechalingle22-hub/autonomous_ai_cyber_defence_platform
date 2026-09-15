"""Unit tests for Real-Time Event Broker and Stream Processing Worker."""

import asyncio
import pytest
from backend.app.streaming.broker import InMemoryEventBroker
from backend.app.streaming.topics import EventTopic
from backend.app.streaming.producer import StreamProducer
from backend.app.streaming.worker import StreamDetectionWorker
from backend.app.schemas.common_event import CommonEventSchema


@pytest.mark.asyncio
async def test_in_memory_broker_publish_and_subscribe():
    """Verifies in-memory publish-subscribe dispatch loop."""
    broker = InMemoryEventBroker(max_queue_size=100)
    received_messages = []

    async def sample_handler(msg):
        received_messages.append(msg)

    broker.subscribe("test.topic", sample_handler)
    await broker.start()

    try:
        await broker.publish("test.topic", {"event_id": "EVT-100", "data": "test_data"})
        # Allow async dispatcher cycle to execute
        await asyncio.sleep(0.1)

        assert len(received_messages) == 1
        assert received_messages[0]["event_id"] == "EVT-100"
        assert "_broker_meta" in received_messages[0]

        stats = broker.get_stats()
        assert stats["stats"]["published_count"] >= 1
        assert stats["stats"]["consumed_count"] >= 1
    finally:
        await broker.stop()


@pytest.mark.asyncio
async def test_dlq_routing_on_handler_error():
    """Verifies that an unhandled processing exception is routed to alerts.dlq."""
    broker = InMemoryEventBroker(max_queue_size=100)

    async def crashing_handler(msg):
        raise ValueError("Simulated parsing crash!")

    broker.subscribe("fragile.topic", crashing_handler)
    await broker.start()

    try:
        await broker.publish("fragile.topic", {"corrupt": "data"})
        await asyncio.sleep(0.1)

        dlq = broker.get_dlq_records()
        assert len(dlq) >= 1
        assert dlq[0]["failed_topic"] == "fragile.topic"
        assert "Simulated parsing crash!" in dlq[0]["error_detail"]
    finally:
        await broker.stop()


@pytest.mark.asyncio
async def test_stream_detection_worker_pipeline():
    """Verifies StreamDetectionWorker validating raw telemetry and triggering detection."""
    broker = InMemoryEventBroker(max_queue_size=100)
    producer = StreamProducer(broker=broker)
    worker = StreamDetectionWorker(broker=broker)
    worker.register_handlers()

    detected_alerts = []
    async def alert_collector(msg):
        detected_alerts.append(msg)

    broker.subscribe(EventTopic.ALERTS_DETECTED.value, alert_collector)
    await broker.start()

    try:
        # 1. Send valid suspicious brute-force event
        brute_event = {
            "source_ip": "192.168.1.150",
            "destination_ip": "10.0.0.12",
            "source_port": 50001,
            "destination_port": 22,
            "protocol": "TCP",
            "event_type": "AUTH",
            "features": {
                "destination_port": 22.0,
                "failed_logins_window": 50.0,
                "bytes_out_ratio": 0.6,
            },
        }
        await producer.send_raw_telemetry(brute_event)
        await asyncio.sleep(0.3)

        # Alert should have been generated and forwarded to ALERTS_DETECTED
        assert len(detected_alerts) >= 1
        alert = detected_alerts[0]
        assert alert["attack_type"] == "BRUTE_FORCE"
        assert alert["severity"] in ["HIGH", "CRITICAL"]
        assert "xai_explanation" in alert

        # 2. Send invalid raw event (violates IP validation)
        invalid_event = {
            "source_ip": "999.999.999.999",  # Invalid IP
            "destination_ip": "10.0.0.1",
        }
        await producer.send_raw_telemetry(invalid_event)
        await asyncio.sleep(0.2)

        dlq_records = broker.get_dlq_records()
        assert len(dlq_records) >= 1
        assert any(r["failed_topic"] == EventTopic.TELEMETRY_RAW.value for r in dlq_records)
    finally:
        await broker.stop()


@pytest.mark.asyncio
async def test_broker_queue_backpressure_drop_oldest():
    """Verifies that when an in-memory topic queue is full, the oldest message is dropped gracefully."""
    broker = InMemoryEventBroker(max_queue_size=3)
    await broker.start()
    try:
        # Publish 4 messages to a queue of capacity 3
        for i in range(4):
            await broker.publish("backpressure.test", {"index": i})

        stats = broker.get_stats()
        # Queue should be at capacity 3 without raising QueueFull
        assert stats["queue_sizes"]["backpressure.test"] <= 3
        assert stats["stats"]["published_count"] >= 3
    finally:
        await broker.stop()


@pytest.mark.asyncio
async def test_broker_multi_subscriber_fanout():
    """Verifies that a message published to a topic is delivered to all registered subscribers."""
    broker = InMemoryEventBroker(max_queue_size=50)
    sub1_msgs = []
    sub2_msgs = []

    async def h1(msg):
        sub1_msgs.append(msg)

    async def h2(msg):
        sub2_msgs.append(msg)

    broker.subscribe("fanout.topic", h1)
    broker.subscribe("fanout.topic", h2)
    await broker.start()

    try:
        await broker.publish("fanout.topic", {"broadcast_id": "BC-1"})
        await asyncio.sleep(0.1)

        assert len(sub1_msgs) == 1
        assert len(sub2_msgs) == 1
        assert sub1_msgs[0]["broadcast_id"] == "BC-1"
        assert sub2_msgs[0]["broadcast_id"] == "BC-1"
    finally:
        await broker.stop()
