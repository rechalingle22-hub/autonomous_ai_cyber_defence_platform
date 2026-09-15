# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Unit tests for Cyber Threat Exposure & Attack Path Validation (APV) Engine."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.exposure.engine import (
    ExposureEngine,
    exposure_engine,
)


def test_default_crown_jewels_loaded():
    """Verifies default enterprise crown jewels are initialized with protection controls."""
    engine = ExposureEngine()
    crown_jewels = engine.get_crown_jewels()
    assert len(crown_jewels) >= 4

    cj_ids = {c["id"] for c in crown_jewels}
    assert "CROWN-01" in cj_ids
    assert "CROWN-02" in cj_ids
    assert "CROWN-03" in cj_ids
    assert "CROWN-04" in cj_ids

    # Verify CROWN-01 details
    cj1 = next(c for c in crown_jewels if c["id"] == "CROWN-01")
    assert cj1["criticality_score"] == 10.0
    assert len(cj1["compensating_controls"]) >= 2
    assert cj1["inbound_paths_count"] >= 1


def test_default_attack_paths_loaded():
    """Verifies discovered multi-hop attack paths have valid nodes and techniques."""
    engine = ExposureEngine()
    paths = engine.get_attack_paths()
    assert len(paths) >= 5

    for path in paths:
        assert path["path_id"].startswith("PATH-")
        assert path["accumulated_risk_score"] > 50.0
        assert path["hop_count"] >= 3
        assert path["status"] == "ACTIVE"
        assert len(path["nodes"]) == path["hop_count"]
        # Check node structure
        for node in path["nodes"]:
            assert node["step_order"] >= 1
            assert node["technique_id"].startswith("T")
            assert node["risk_contribution"] > 0


def test_default_choke_points_loaded():
    """Verifies graph choke points and minimal cut set disruption efficiencies."""
    engine = ExposureEngine()
    cps = engine.get_choke_points()
    assert len(cps) >= 4

    cp1 = next(c for c in cps if c["choke_point_id"] == "CP-01")
    assert cp1["affected_paths_count"] >= 3
    assert cp1["disruption_efficiency_percent"] >= 70.0
    assert cp1["is_remediated"] is False


def test_remediate_choke_point_severs_paths():
    """Verifies remediating a choke point severs intersecting paths and boosts resilience."""
    engine = ExposureEngine()
    initial_metrics = engine.get_metrics()
    assert initial_metrics["severed_attack_paths_count"] == 0

    result = engine.remediate_choke_point("CP-01")
    assert result["choke_point_id"] == "CP-01"
    assert result["severed_paths_count"] >= 2
    assert "PATH-001" in result["severed_path_ids"]
    assert result["new_resilience_index"] > initial_metrics["attack_path_resilience_index"]

    # Verify path statuses updated
    p1 = engine.attack_paths["PATH-001"]
    assert p1["status"] == "SEVERED"
    assert p1["severed_by_choke_point"] == "CP-01"

    updated_metrics = engine.get_metrics()
    assert updated_metrics["severed_attack_paths_count"] >= 2
    assert updated_metrics["active_attack_paths_count"] < initial_metrics["active_attack_paths_count"]


def test_remediate_unknown_choke_point():
    """Verifies error handling when attempting to remediate a non-existent choke point."""
    engine = ExposureEngine()
    with pytest.raises(KeyError):
        engine.remediate_choke_point("CP-NONEXISTENT-999")


def test_reset_remediations():
    """Verifies resetting exposure graph restores all severed paths to active baseline."""
    engine = ExposureEngine()
    engine.remediate_choke_point("CP-01")
    assert engine.get_metrics()["severed_attack_paths_count"] >= 2

    engine.reset_remediations()
    metrics = engine.get_metrics()
    assert metrics["severed_attack_paths_count"] == 0
    assert metrics["active_attack_paths_count"] == metrics["total_attack_paths_discovered"]
    assert all(p["status"] == "ACTIVE" for p in engine.attack_paths.values())
    assert all(not c["is_remediated"] for c in engine.choke_points.values())

