# pyright: reportMissingImports=false
# pyright: reportMissingModuleSource=false
"""API integration tests for User and Entity Behavior Analytics (UEBA) endpoints."""

import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone



@pytest.mark.asyncio
async def test_ueba_status_endpoint(async_client: AsyncClient):
    """Verifies that the UEBA status endpoint reports active tracking metrics."""
    resp = await async_client.get("/api/v1/ueba/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "OPERATIONAL"
    assert "tracked_users" in data
    assert "tracked_hosts" in data
    assert "recent_anomalies_count" in data


@pytest.mark.asyncio
async def test_ueba_evaluate_benign_and_anomalous(async_client: AsyncClient):
    """Verifies behavioral evaluation for routine telemetry and anomalous surges."""
    # 1. Evaluate normal event
    normal_event = {
        "user_id": "corp_user_42",
        "source_ip": "10.0.3.15",
        "destination_port": 443,
        "features": {
            "bytes_out": 200.0,
            "failed_logins_window": 0.0,
        },
    }
    resp1 = await async_client.post("/api/v1/ueba/evaluate", json=normal_event)
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert "is_anomaly" in data1
    assert "anomaly_score" in data1

    # 2. Seed baseline with normal operations
    seed_payload = {
        "count": 15,
        "avg_bytes_out": 250.0,
        "avg_flow_duration_ms": 100.0,
    }
    seed_resp = await async_client.post("/api/v1/ueba/baselines/user/corp_user_42/seed", json=seed_payload)
    assert seed_resp.status_code == 200

    # 3. Evaluate anomalous surge (e.g. 40 failed logins)
    surge_event = {
        "user_id": "corp_user_42",
        "source_ip": "10.0.3.15",
        "destination_port": 22,
        "features": {
            "bytes_out": 250.0,
            "failed_logins_window": 40.0,
        },
    }
    resp2 = await async_client.post("/api/v1/ueba/evaluate", json=surge_event)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["is_anomaly"] is True
    assert "FAILED_LOGINS_SPIKE" in data2["flags"]
    assert data2["severity"] in ["HIGH", "CRITICAL"]


@pytest.mark.asyncio
async def test_ueba_baseline_retrieval_and_404(async_client: AsyncClient):
    """Verifies baseline retrieval and 404 behavior for unknown entities."""
    # 1. Non-existent user
    resp_404 = await async_client.get("/api/v1/ueba/baselines/user/unknown_entity_999")
    assert resp_404.status_code == 404

    # 2. Seed and retrieve known user
    seed_payload = {"count": 10, "avg_bytes_out": 500.0}
    await async_client.post("/api/v1/ueba/baselines/user/analyst_mark/seed", json=seed_payload)

    resp_get = await async_client.get("/api/v1/ueba/baselines/user/analyst_mark")
    assert resp_get.status_code == 200
    profile = resp_get.json()
    assert profile["entity_id"] == "analyst_mark"
    assert profile["total_events"] >= 10
    assert "metrics" in profile


@pytest.mark.asyncio
async def test_ueba_impossible_travel_endpoint(async_client: AsyncClient):
    """Verifies the dedicated impossible travel calculation endpoint."""
    t0 = datetime(2026, 9, 1, 14, 0, 0, tzinfo=timezone.utc)
    t_impossible = t0 + timedelta(minutes=20)
    t_feasible = t0 + timedelta(hours=10)

    # 1. New York -> London in 20 minutes (impossible)
    impossible_req = {
        "origin_lat": 40.7128,
        "origin_lon": -74.0060,
        "origin_timestamp": t0.isoformat(),
        "origin_city": "New York",
        "dest_lat": 51.5074,
        "dest_lon": -0.1278,
        "dest_timestamp": t_impossible.isoformat(),
        "dest_city": "London",
    }
    resp1 = await async_client.post("/api/v1/ueba/impossible-travel", json=impossible_req)
    assert resp1.status_code == 200
    res1 = resp1.json()
    assert res1["is_impossible"] is True
    assert res1["speed_kmh"] > 900.0
    assert res1["severity"] == "CRITICAL"

    # 2. New York -> London in 10 hours (feasible)
    feasible_req = {
        **impossible_req,
        "dest_timestamp": t_feasible.isoformat(),
    }
    resp2 = await async_client.post("/api/v1/ueba/impossible-travel", json=feasible_req)
    assert resp2.status_code == 200
    res2 = resp2.json()
    assert res2["is_impossible"] is False
    assert res2["severity"] == "INFO"


@pytest.mark.asyncio
async def test_ueba_anomalies_list(async_client: AsyncClient):
    """Verifies retrieval of recent high-deviation anomalies."""
    resp = await async_client.get("/api/v1/ueba/anomalies?limit=25")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

