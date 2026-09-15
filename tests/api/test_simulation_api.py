"""API integration tests for Cyber Range simulations."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_simulation_scenarios(async_client: AsyncClient):
    """Verifies that all standard Cyber Range scenarios are listed."""
    resp = await async_client.get("/api/v1/simulations/scenarios")
    assert resp.status_code == 200
    scenarios = resp.json()
    scenario_ids = [s["scenario_id"] for s in scenarios]
    assert "BENIGN" in scenario_ids
    assert "SCENARIO_1" in scenario_ids
    assert "SCENARIO_2" in scenario_ids
    assert "SCENARIO_3" in scenario_ids
    assert "SCENARIO_4" in scenario_ids
    assert "SCENARIO_5" in scenario_ids


@pytest.mark.asyncio
async def test_run_simulation_scenario_1(async_client: AsyncClient):
    """Tests executing Scenario 1 and verifies telemetry is ingested and queryable."""
    payload = {
        "scenario_id": "SCENARIO_1",
        "event_count": 10,
    }
    resp = await async_client.post("/api/v1/simulations/run", json=payload)
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "SIMULATION_EXECUTED"
    assert data["scenario_id"] == "SCENARIO_1"
    assert data["events_ingested"] == 10
    assert len(data["sample_event_ids"]) > 0

    # Verify events exist in database via telemetry listing endpoint
    events_resp = await async_client.get("/api/v1/telemetry/events?source_ip=192.168.1.150")
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) >= 10
    assert events[0]["event_type"] == "AUTH"


@pytest.mark.asyncio
async def test_run_simulation_invalid_scenario_rejected(async_client: AsyncClient):
    """Verifies that an unknown scenario ID returns HTTP 400 Bad Request."""
    payload = {
        "scenario_id": "NON_EXISTENT_SCENARIO",
        "event_count": 5,
    }
    resp = await async_client.post("/api/v1/simulations/run", json=payload)
    assert resp.status_code == 400
    assert "Unknown scenario ID" in resp.json()["detail"]

