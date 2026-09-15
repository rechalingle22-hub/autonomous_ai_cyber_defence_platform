# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Security Chaos Engineering & Resilience Engine."""

import os
import sys
import time
from datetime import datetime, timezone, timedelta
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.chaos.engine import SecurityChaosEngine, ChaosType, chaos_engine
from backend.app.database.redis_client import redis_manager
from backend.app.database.neo4j_client import neo4j_manager


@pytest.fixture(autouse=True)
def clean_chaos_state():
    """Ensure chaos engine is always reset before and after each test."""
    chaos_engine.recover_all()
    yield
    chaos_engine.recover_all()


def test_inject_broker_latency():
    """Verifies injecting broker latency bounded experiment."""
    engine = SecurityChaosEngine()
    exp = engine.inject_chaos(
        experiment_type=ChaosType.BROKER_LATENCY,
        duration_seconds=15,
        params={"latency_ms": 500},
    )

    assert exp["status"] == "ACTIVE"
    assert exp["experiment_type"] == "BROKER_LATENCY"
    assert exp["duration_seconds"] == 15
    assert exp["metrics"]["latency_injected_ms"] == 500
    assert exp["id"] in engine.active_experiments


def test_inject_db_partition_activates_fallbacks():
    """Verifies DB partition isolates managers and engages fallback drivers."""
    engine = SecurityChaosEngine()
    exp = engine.inject_chaos(
        experiment_type=ChaosType.DB_PARTITION,
        duration_seconds=10,
        params={"target_db": "ALL"},
    )

    assert exp["status"] == "ACTIVE"
    assert exp["metrics"]["fallback_engaged"] is True

    # Check managers entered fallback state
    assert redis_manager._is_connected is False
    assert neo4j_manager._is_connected is False

    # Recover experiment
    engine.recover_experiment(exp["id"])
    assert redis_manager._is_connected is True
    assert neo4j_manager._is_connected is True


def test_duration_boundary_clamping():
    """Verifies duration is strictly clamped between 5s and 120s."""
    engine = SecurityChaosEngine()

    exp_short = engine.inject_chaos(ChaosType.BROKER_DROP, duration_seconds=1)
    assert exp_short["duration_seconds"] == 5

    exp_long = engine.inject_chaos(ChaosType.BROKER_DROP, duration_seconds=500)
    assert exp_long["duration_seconds"] == 120


def test_auto_cleanup_expired_experiments():
    """Verifies expired leases are automatically cleaned up on next engine check."""
    engine = SecurityChaosEngine()
    exp = engine.inject_chaos(ChaosType.AGENT_TIMEOUT, duration_seconds=5)

    # Force expiration timestamp into the past
    past_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    engine.active_experiments[exp["id"]]["expires_at"] = past_time

    # Trigger score calculation or cleanup
    status = engine.calculate_resilience_score()
    assert exp["id"] not in engine.active_experiments
    assert status["active_faults_count"] == 0
    assert status["system_state"] == "STEADY_STATE"


def test_recover_all_emergency_abort():
    """Verifies recover_all immediately flushes all active experiments and restores steady state."""
    engine = SecurityChaosEngine()
    engine.inject_chaos(ChaosType.BROKER_LATENCY, duration_seconds=30)
    engine.inject_chaos(ChaosType.TELEMETRY_BURST, duration_seconds=30)
    engine.inject_chaos(ChaosType.DB_PARTITION, duration_seconds=30)

    assert len(engine.active_experiments) == 3

    recovered = engine.recover_all(reason="EMERGENCY_ABORT")
    assert len(recovered) == 3
    assert len(engine.active_experiments) == 0
    assert redis_manager._is_connected is True
    assert neo4j_manager._is_connected is True

    status = engine.calculate_resilience_score()
    assert status["resilience_score"] == 100.0
    assert status["system_state"] == "STEADY_STATE"

