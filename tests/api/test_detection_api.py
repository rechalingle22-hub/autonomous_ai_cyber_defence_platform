"""API integration tests for real-time detection inference endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_detection_status(async_client: AsyncClient):
    """Verifies that the detection status endpoint reports loaded models and parameters."""
    resp = await async_client.get("/api/v1/detection/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "is_ready" in data
    assert "models_loaded" in data
    assert "thresholds" in data


@pytest.mark.asyncio
async def test_analyze_benign_event(async_client: AsyncClient):
    """Verifies that normal benign telemetry scores as low anomaly."""
    benign_payload = {
        "source_ip": "10.0.1.15",
        "destination_ip": "8.8.8.8",
        "source_port": 51234,
        "destination_port": 53,
        "protocol": "UDP",
        "event_type": "DNS",
        "severity": "INFO",
        "features": {
            "flow_duration_ms": 150.0,
            "total_fwd_packets": 8.0,
            "total_bwd_packets": 8.0,
            "total_fwd_bytes": 512.0,
            "total_bwd_bytes": 1024.0,
            "flow_bytes_per_sec": 10240.0,
            "destination_port": 53.0,
            "failed_logins_window": 0.0,
            "port_entropy": 0.2,
            "bytes_out_ratio": 0.33,
        },
    }
    resp = await async_client.post("/api/v1/detection/analyze", json=benign_payload)
    assert resp.status_code == 200
    result = resp.json()
    assert result["prediction"] == "benign"
    assert result["anomaly_score"] < 0.65
    assert result["severity"] in ["LOW", "MEDIUM"]
    assert "isolation_forest" in result["detectors"]
    assert "autoencoder" in result["detectors"]


@pytest.mark.asyncio
async def test_analyze_anomalous_exfiltration_event(async_client: AsyncClient):
    """Verifies that extreme anomalous exfiltration telemetry scores as suspicious/high."""
    exfil_payload = {
        "source_ip": "10.0.1.75",
        "destination_ip": "198.51.100.42",
        "source_port": 55100,
        "destination_port": 443,
        "protocol": "TCP",
        "event_type": "NETFLOW",
        "severity": "HIGH",
        "features": {
            "flow_duration_ms": 15000.0,
            "total_fwd_packets": 9000.0,
            "total_bwd_packets": 20.0,
            "total_fwd_bytes": 85000000.0,  # 85 MB
            "total_bwd_bytes": 2000.0,
            "flow_bytes_per_sec": 5666666.0,
            "destination_port": 443.0,
            "failed_logins_window": 0.0,
            "port_entropy": 0.02,
            "bytes_out_ratio": 0.999,
        },
    }
    resp = await async_client.post("/api/v1/detection/analyze", json=exfil_payload)
    assert resp.status_code == 200
    result = resp.json()
    assert result["prediction"] == "suspicious"
    assert result["anomaly_score"] >= 0.65
    assert result["severity"] in ["HIGH", "CRITICAL"]


@pytest.mark.asyncio
async def test_analyze_batch_events(async_client: AsyncClient):
    """Verifies batch inference endpoint on multiple mixed events."""
    batch_payload = {
        "events": [
            {
                "source_ip": "10.0.1.10",
                "destination_ip": "1.1.1.1",
                "source_port": 45000,
                "destination_port": 53,
                "protocol": "UDP",
                "event_type": "DNS",
            },
            {
                "source_ip": "192.168.1.150",
                "destination_ip": "10.0.0.12",
                "source_port": 50001,
                "destination_port": 22,
                "protocol": "TCP",
                "event_type": "AUTH",
                "features": {"failed_logins_window": 25.0, "destination_port": 22.0},
            },
        ]
    }
    resp = await async_client.post("/api/v1/detection/analyze-batch", json=batch_payload)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 2
    assert "anomaly_score" in results[0]
    assert "anomaly_score" in results[1]

