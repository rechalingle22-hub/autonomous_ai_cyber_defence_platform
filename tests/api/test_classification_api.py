"""API integration tests for attack classification and explainable AI endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_classification_status_includes_all_models(async_client: AsyncClient):
    """Verifies that /status reports operational status of supervised models and XAI."""
    resp = await async_client.get("/api/v1/detection/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_ready"] is True
    models = data["models_loaded"]
    assert models["isolation_forest"] is True
    assert models["autoencoder"] is True
    assert models["random_forest"] is True
    assert models["xgboost"] is True
    assert models["shap_explainer"] is True
    assert len(data["classes"]) > 0


@pytest.mark.asyncio
async def test_classify_benign_event(async_client: AsyncClient):
    """Verifies that benign traffic classifies as BENIGN with high confidence."""
    benign_payload = {
        "source_ip": "10.0.1.20",
        "destination_ip": "8.8.8.8",
        "source_port": 52140,
        "destination_port": 53,
        "protocol": "UDP",
        "event_type": "DNS",
        "severity": "INFO",
        "features": {
            "flow_duration_ms": 50.0,
            "total_fwd_packets": 2.0,
            "total_bwd_packets": 2.0,
            "total_fwd_bytes": 128.0,
            "total_bwd_bytes": 256.0,
            "flow_bytes_per_sec": 7680.0,
            "destination_port": 53.0,
            "failed_logins_window": 0.0,
            "port_entropy": 0.1,
            "bytes_out_ratio": 0.33,
        },
    }
    resp = await async_client.post("/api/v1/detection/classify", json=benign_payload)
    assert resp.status_code == 200
    res = resp.json()
    assert res["prediction"] == "benign"
    assert res["attack_type"] == "BENIGN"
    assert res["confidence"] >= 0.4
    assert "xai_explanation" in res
    assert "latency_ms" in res


@pytest.mark.asyncio
async def test_classify_brute_force_attack_with_xai(async_client: AsyncClient):
    """Verifies that brute force traffic classifies accurately with SHAP feature attribution."""
    brute_force_payload = {
        "source_ip": "192.168.1.105",
        "destination_ip": "10.0.0.5",
        "source_port": 49152,
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "AUTH",
        "severity": "HIGH",
        "features": {
            "flow_duration_ms": 120.0,
            "total_fwd_packets": 6.0,
            "total_bwd_packets": 6.0,
            "total_fwd_bytes": 450.0,
            "total_bwd_bytes": 450.0,
            "flow_bytes_per_sec": 7500.0,
            "destination_port": 22.0,
            "failed_logins_window": 45.0,  # High failed login rate
            "port_entropy": 0.05,
            "bytes_out_ratio": 0.5,
        },
    }
    resp = await async_client.post("/api/v1/detection/classify", json=brute_force_payload)
    assert resp.status_code == 200
    res = resp.json()
    assert res["prediction"] == "suspicious"
    assert res["attack_type"] == "BRUTE_FORCE"
    assert res["confidence"] >= 0.6
    assert res["severity"] in ["HIGH", "CRITICAL"]

    xai = res["xai_explanation"]
    assert xai["predicted_category"] == "BRUTE_FORCE"
    assert xai["explanation_method"] == "TreeSHAP"
    assert len(xai["contributing_factors"]) > 0

    # Ensure failed_logins_window is among the top drivers
    top_feature_names = [f["feature"] for f in xai["contributing_factors"]]
    assert "failed_logins_window" in top_feature_names


@pytest.mark.asyncio
async def test_analyze_endpoint_fusion(async_client: AsyncClient):
    """Verifies that /analyze fuses anomaly detection, classification, and XAI."""
    payload = {
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
            "total_fwd_bytes": 85000000.0,
            "total_bwd_bytes": 2000.0,
            "flow_bytes_per_sec": 5666666.0,
            "destination_port": 443.0,
            "failed_logins_window": 0.0,
            "port_entropy": 0.02,
            "bytes_out_ratio": 0.999,
        },
    }
    resp = await async_client.post("/api/v1/detection/analyze", json=payload)
    assert resp.status_code == 200
    res = resp.json()
    assert "anomaly_score" in res
    assert "attack_type" in res
    assert "detectors" in res
    assert "xgboost" in res["detectors"]
    assert "random_forest" in res["detectors"]
    assert "xai_explanation" in res
