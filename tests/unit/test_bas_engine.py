# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Unit tests for Breach and Attack Simulation (BAS) Engine."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.bas.engine import (
    BasEngine,
    StageStatus,
    bas_engine,
)


def test_default_campaigns_loaded():
    """Verifies curated APT adversary campaigns are properly initialized."""
    engine = BasEngine()
    campaigns = engine.get_campaigns()
    assert len(campaigns) >= 4

    campaign_ids = {c["campaign_id"] for c in campaigns}
    assert "APT29" in campaign_ids
    assert "FIN7" in campaign_ids
    assert "LAZARUS" in campaign_ids
    assert "BLACKCAT" in campaign_ids

    # Verify APT29 details
    apt29 = engine.get_campaign("APT29")
    assert "Cozy Bear" in apt29["name"]
    assert len(apt29["stages"]) == 8
    for stage in apt29["stages"]:
        assert stage["technique_id"].startswith("T")
        assert stage["tactic"] is not None
        assert stage["default_detecting_layer"] is not None
        assert stage["default_outcome"] in (StageStatus.PREVENTED, StageStatus.DETECTED, StageStatus.EVADED)


def test_get_campaign_valid_and_invalid():
    """Verifies campaign retrieval and error handling for unknown IDs."""
    engine = BasEngine()
    # Case-insensitive
    camp = engine.get_campaign("apt29")
    assert camp["campaign_id"] == "APT29"

    with pytest.raises(KeyError):
        engine.get_campaign("UNKNOWN_APT_999")


def test_execute_campaign_apt29():
    """Verifies non-destructive multi-stage simulation execution for APT29."""
    engine = BasEngine()
    initial_history_len = len(engine.simulation_history)

    result = engine.execute_campaign(
        campaign_id="APT29",
        target_environment="Staging Cloud Enclave",
        dry_run=False,
    )

    assert result["simulation_id"].startswith("sim-")
    assert result["campaign_id"] == "APT29"
    assert result["total_stages"] == 8
    assert result["prevented_stages"] > 0
    assert result["detection_rate_percent"] >= 80.0
    assert result["posture_score"] >= 75.0
    assert result["summary_verdict"] in ("STRONG_RESILIENCE", "MODERATE_RESILIENCE")
    assert len(result["stage_results"]) == 8
    assert len(engine.simulation_history) == initial_history_len + 1


def test_execute_campaign_dry_run():
    """Verifies dry-run mode does not pollute historical logs."""
    engine = BasEngine()
    initial_history_len = len(engine.simulation_history)

    result = engine.execute_campaign(
        campaign_id="FIN7",
        dry_run=True,
    )

    assert result["dry_run"] is True
    assert len(engine.simulation_history) == initial_history_len


def test_execute_all_adversary_profiles():
    """Verifies simulation runs smoothly across FIN7, Lazarus, and BlackCat."""
    engine = BasEngine()
    for cid in ["FIN7", "LAZARUS", "BLACKCAT"]:
        res = engine.execute_campaign(campaign_id=cid)
        assert res["total_stages"] >= 6
        assert res["prevention_rate_percent"] > 50.0
        assert res["mean_time_to_block_ms"] > 0


def test_coverage_matrix_and_metrics():
    """Verifies ATT&CK matrix and aggregate posture metrics."""
    engine = BasEngine()
    matrix = engine.get_coverage_matrix()
    assert len(matrix) >= 25

    # Check a specific technique
    t1566 = next((t for t in matrix if t["technique_id"] == "T1566.001"), None)
    assert t1566 is not None
    assert t1566["status"] in ("PREVENTED", "DETECTED", "EVADED")

    metrics = engine.get_metrics()
    assert metrics["overall_posture_score"] > 0
    assert metrics["total_campaigns_available"] >= 4
    assert metrics["total_simulations_executed"] >= 2
    assert metrics["detection_rate_percent"] > 80.0
    assert metrics["mitre_techniques_covered"] >= 25

