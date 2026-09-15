"""API integration tests for Real-Time Streaming REST endpoints."""

import asyncio
import pytest
from httpx import AsyncClient
from backend.app.streaming.broker import event_broker
from backend.app.streaming.worker import stream_worker


@pytest.mark.asyncio
async def test_streaming_status(async_client: AsyncClient):
    """Verifies that the streaming status endpoint reports active broker stats and topics."""
    resp = await async_client.get("/api/v1/streaming/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "broker_type" in data
    assert "is_running" in data
    assert "queue_sizes" in data
    assert "subscriber_counts" in data
    assert "telemetry.raw" in data["queue_sizes"]
    assert "telemetry.normalized" in data["queue_sizes"]


@pytest.mark.asyncio
async def test_publish_raw_valid_and_dlq_inspection(async_client: AsyncClient):
    """Verifies publishing raw telemetry, queueing, and DLQ handling on invalid input."""
    # Ensure broker is running and worker registered
    stream_worker.register_handlers()
    await event_broker.start()

    # 1. Publish valid raw telemetry
    valid_raw = {
        "source_ip": "10.0.1.15",
        "destination_ip": "8.8.8.8",
        "source_port": 53000,
        "destination_port": 53,
        "protocol": "UDP",
        "event_type": "DNS",
        "features": {
            "flow_duration_ms": 40.0,
            "destination_port": 53.0,
        },
    }
    resp1 = await async_client.post("/api/v1/streaming/publish/raw", json=valid_raw)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "QUEUED_RAW"

    # 2. Publish invalid raw telemetry (invalid IP)
    invalid_raw = {
        "source_ip": "not.an.ip.address",
        "destination_ip": "10.0.0.1",
        "source_port": 1234,
        "destination_port": 80,
    }
    resp2 = await async_client.post("/api/v1/streaming/publish/raw", json=invalid_raw)
    assert resp2.status_code == 200

    # Allow async worker cycle to process and route to DLQ
    await asyncio.sleep(0.3)

    # 3. Query DLQ records
    dlq_resp = await async_client.get("/api/v1/streaming/dlq")
    assert dlq_resp.status_code == 200
    dlq_records = dlq_resp.json()
    assert len(dlq_records) >= 1
    assert any(
        "Invalid IP address format" in str(r.get("error_detail", ""))
        for r in dlq_records
    )


@pytest.mark.asyncio
async def test_publish_normalized_and_batch(async_client: AsyncClient):
    """Verifies direct normalized stream ingestion and batch streaming."""
    stream_worker.register_handlers()
    await event_broker.start()

    # 1. Single normalized event
    norm_event = {
        "source_ip": "10.0.2.20",
        "destination_ip": "10.0.0.50",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "TCP",
        "event_type": "NETFLOW",
        "features": {
            "flow_duration_ms": 250.0,
            "destination_port": 443.0,
        },
    }
    resp1 = await async_client.post("/api/v1/streaming/publish/normalized", json=norm_event)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "QUEUED_NORMALIZED"

    # 2. Batch ingestion
    batch_payload = {
        "events": [
            {
                "source_ip": "10.0.1.30",
                "destination_ip": "1.1.1.1",
                "source_port": 45000,
                "destination_port": 53,
                "protocol": "UDP",
                "event_type": "DNS",
            },
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "10.0.0.1",
                "source_port": 50000,
                "destination_port": 80,
                "protocol": "TCP",
                "event_type": "APPLICATION",
            },
        ]
    }
    resp2 = await async_client.post("/api/v1/streaming/publish/batch", json=batch_payload)
    assert resp2.status_code == 200
    assert resp2.json()["count"] == 2


@pytest.mark.asyncio
async def test_publish_normalized_invalid_payload_returns_422(async_client: AsyncClient):
    """Verifies that invalid schema fields return 422 Unprocessable Entity."""
    invalid_payload = {
        "source_ip": "invalid-ip",
        "destination_ip": "10.0.0.1",
    }
    resp = await async_client.post("/api/v1/streaming/publish/normalized", json=invalid_payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_publish_batch_invalid_items_returns_422(async_client: AsyncClient):
    """Verifies that malformed items inside a batch return 422 Unprocessable Entity."""
    bad_batch = {
        "events": [
            {
                "source_ip": "not_an_ip",
                "destination_ip": "1.1.1.1",
            }
        ]
    }
    resp = await async_client.post("/api/v1/streaming/publish/batch", json=bad_batch)
    assert resp.status_code == 422

