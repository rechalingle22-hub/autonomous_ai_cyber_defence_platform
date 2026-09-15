# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Streaming REST API router for broker monitoring, ingestion, and DLQ inspection."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path:
        sys.path.insert(0, p)

from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from backend.app.streaming.broker import event_broker
from backend.app.streaming.producer import stream_producer
from backend.app.schemas.common_event import CommonEventSchema

router = APIRouter(prefix="/streaming", tags=["Real-Time Streaming Pipeline"])


class BatchStreamRequest(BaseModel):
    events: List[CommonEventSchema]


@router.get("/status")
async def get_streaming_status() -> Dict[str, Any]:
    """Returns streaming broker state, throughput statistics, and topic queue depths."""
    return event_broker.get_stats()


@router.post("/publish/raw")
async def publish_raw_event(raw_event: Dict[str, Any]) -> Dict[str, str]:
    """Ingests raw unvalidated telemetry for stream normalization, validation, and detection."""
    try:
        await stream_producer.send_raw_telemetry(raw_event)
        return {"status": "QUEUED_RAW", "topic": "telemetry.raw"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to publish raw telemetry: {str(e)}",
        )


@router.post("/publish/normalized")
async def publish_normalized_event(event: CommonEventSchema) -> Dict[str, str]:
    """Ingests pre-validated telemetry directly to the detection inference stream."""
    try:
        await stream_producer.send_normalized_event(event)
        return {"status": "QUEUED_NORMALIZED", "topic": "telemetry.normalized"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to publish normalized telemetry: {str(e)}",
        )


@router.post("/publish/batch")
async def publish_batch_events(req: BatchStreamRequest) -> Dict[str, Any]:
    """Publishes a batch of telemetry events onto the streaming pipeline."""
    try:
        count = await stream_producer.send_batch_telemetry(req.events)
        return {"status": "BATCH_QUEUED", "count": count, "topic": "telemetry.normalized"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to publish telemetry batch: {str(e)}",
        )


@router.get("/dlq")
async def get_dlq_records(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent Dead-Letter Queue (DLQ) records for triage and inspection."""
    if hasattr(event_broker, "get_dlq_records"):
        return event_broker.get_dlq_records(limit=limit)
    return []

