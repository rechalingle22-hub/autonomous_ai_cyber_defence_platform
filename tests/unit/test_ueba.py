# pyright: reportMissingImports=false
# pyright: reportMissingModuleSource=false
"""Unit tests for UEBA Behavioral Analytics, Welford Statistics, and Geo-Velocity."""

import pytest
import math

from datetime import datetime, timedelta, timezone

from backend.app.ueba.baseline import MetricStats, EntityBaseline, BaselineStore
from backend.app.ueba.geo_velocity import (
    GeoPoint,
    haversine_distance_km,
    calculate_velocity_kmh,
    detect_impossible_travel,
)
from backend.app.ueba.engine import UEBAEngine


def test_welford_stats_accuracy():
    """Verifies that Welford's algorithm computes exact sample mean and variance in a single pass."""
    stats = MetricStats()
    data = [10.0, 20.0, 30.0, 40.0, 50.0]

    for x in data:
        stats.update(x)

    assert stats.count == 5
    assert stats.mean == 30.0
    # Sample variance for [10, 20, 30, 40, 50]: sum((x-30)^2)/(5-1) = 1000 / 4 = 250.0
    assert stats.variance == 250.0
    assert abs(stats.std_dev - math.sqrt(250.0)) < 1e-6
    assert stats.min_val == 10.0
    assert stats.max_val == 50.0


def test_z_score_calculation_and_floor():
    """Verifies Z-Score computation with zero-variance protection."""
    stats = MetricStats()
    # 5 identical observations -> variance = 0
    for _ in range(5):
        stats.update(5.0)

    assert stats.variance == 0.0
    assert stats.std_dev == 0.0

    # With min_std floor of 1.0: (10.0 - 5.0) / 1.0 = 5.0
    z = stats.z_score(10.0, min_std=1.0)
    assert z == 5.0


def test_haversine_great_circle_distance():
    """Verifies Haversine distance calculation between New York and London (~5570 km)."""
    ny_lat, ny_lon = 40.7128, -74.0060
    lon_lat, lon_lon = 51.5074, -0.1278

    dist = haversine_distance_km(ny_lat, ny_lon, lon_lat, lon_lon)
    # Expected distance: ~5570 km
    assert 5500.0 <= dist <= 5650.0


def test_impossible_travel_detection():
    """Verifies impossible travel detection when velocity exceeds commercial flight limits (>900 km/h)."""
    t0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Point A: New York at 12:00
    p1 = GeoPoint(latitude=40.7128, longitude=-74.0060, timestamp=t0, city="New York", ip="198.51.100.1")

    # Point B1: London 30 minutes later (impossible velocity: ~11,000 km/h)
    p2_impossible = GeoPoint(
        latitude=51.5074,
        longitude=-0.1278,
        timestamp=t0 + timedelta(minutes=30),
        city="London",
        ip="203.0.113.5",
    )
    res_impossible = detect_impossible_travel(p1, p2_impossible)
    assert res_impossible["is_impossible"] is True
    assert res_impossible["severity"] == "CRITICAL"
    assert res_impossible["speed_kmh"] > 900.0

    # Point B2: London 8 hours later (feasible velocity: ~700 km/h)
    p2_feasible = GeoPoint(
        latitude=51.5074,
        longitude=-0.1278,
        timestamp=t0 + timedelta(hours=8),
        city="London",
        ip="203.0.113.5",
    )
    res_feasible = detect_impossible_travel(p1, p2_feasible)
    assert res_feasible["is_impossible"] is False
    assert res_feasible["severity"] == "INFO"
    assert res_feasible["speed_kmh"] < 900.0


def test_shannon_port_entropy():
    """Verifies Shannon entropy: 0 for single port, log2(N) for uniform distribution."""
    baseline = EntityBaseline("host", "10.0.1.50")

    # 1. Single port accessed 50 times -> Entropy = 0
    for _ in range(50):
        baseline.update(features={}, dst_port=443)
    assert baseline.calculate_shannon_entropy() == 0.0

    # 2. Reset and access 8 distinct ports with equal frequency (10 each) -> Entropy = log2(8) = 3.0
    baseline_uniform = EntityBaseline("host", "10.0.1.55")
    ports = [80, 443, 22, 21, 25, 53, 8080, 8443]
    for port in ports:
        for _ in range(10):
            baseline_uniform.update(features={}, dst_port=port)
    assert abs(baseline_uniform.calculate_shannon_entropy() - 3.0) < 0.01


def test_off_hours_detection():
    """Verifies that events during unusual entity hours trigger OFF_HOURS_ACCESS."""
    store = BaselineStore()
    engine = UEBAEngine(store=store)
    user_baseline = store.get_or_create("user", "analyst_alice")

    # Seed 30 events strictly during business hours (10:00 to 16:00 UTC)
    for i in range(30):
        hour = 10 + (i % 6)
        user_baseline.update(
            features={"failed_logins_window": 0.0, "bytes_out": 100.0},
            timestamp=datetime(2026, 9, 1, hour, 0, 0, tzinfo=timezone.utc),
        )

    # Event at 03:00 UTC (off-hours for this user)
    off_hours_event = {
        "user_id": "analyst_alice",
        "source_ip": "10.0.2.10",
        "timestamp": datetime(2026, 9, 2, 3, 30, 0, tzinfo=timezone.utc).isoformat(),
        "features": {"failed_logins_window": 0.0, "bytes_out": 100.0},
    }
    result = engine.evaluate_event(off_hours_event)
    assert "OFF_HOURS_ACCESS" in result["flags"]
    assert result["is_anomaly"] is True


def test_ueba_engine_failed_logins_spike():
    """Verifies that an abrupt surge in failed logins triggers FAILED_LOGINS_SPIKE via Z-score."""
    store = BaselineStore()
    engine = UEBAEngine(store=store)
    baseline = store.get_or_create("user", "user_bob")

    # Seed 10 events with low failed logins (0-1)
    for _ in range(10):
        baseline.update(features={"failed_logins_window": 0.2})

    # Sudden surge: 35 failed logins in window
    surge_event = {
        "user_id": "user_bob",
        "source_ip": "10.0.1.200",
        "features": {"failed_logins_window": 35.0},
    }
    eval_result = engine.evaluate_event(surge_event)
    assert "FAILED_LOGINS_SPIKE" in eval_result["flags"]
    assert eval_result["anomaly_score"] >= 0.70
    assert eval_result["severity"] in ["HIGH", "CRITICAL"]

