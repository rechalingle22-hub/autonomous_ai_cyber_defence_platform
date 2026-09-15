# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Threat Hunting & Autonomous Detection-as-Code Engine."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.threathunting.engine import (
    ThreatHuntingEngine,
    RuleFormat,
    RuleStatus,
    HuntConfidence,
    threathunting_engine,
)


def test_hypothesis_catalog_seeding():
    """Verifies default adversary hunting hypotheses covering key MITRE techniques."""
    engine = ThreatHuntingEngine()
    assert len(engine.hypotheses) >= 5

    hyp_01 = engine.hypotheses.get("HYP-001")
    assert hyp_01 is not None
    assert hyp_01["mitre_technique"] == "T1071.004"
    assert "DNS" in hyp_01["title"]
    assert len(hyp_01["simulated_iocs"]) >= 1

    hyp_02 = engine.hypotheses.get("HYP-002")
    assert hyp_02 is not None
    assert hyp_02["mitre_technique"] == "T1059.001"
    assert "certutil" in hyp_02["query_logic"]


def test_execute_hunt_success():
    """Verifies executing a hypothesis hunt across telemetry logs."""
    engine = ThreatHuntingEngine()
    initial_hunts = len(engine.hunt_executions)

    result = engine.execute_hunt(hypothesis_id="HYP-001", time_window_hours=48)

    assert result["hypothesis_id"] == "HYP-001"
    assert result["findings_count"] >= 1
    assert result["confidence_score"] >= 80.0
    assert result["confidence_level"] in (HuntConfidence.CRITICAL_CONFIRMED.value, HuntConfidence.HIGH_LIKELIHOOD.value)
    assert len(result["matched_iocs"]) >= 1
    assert len(result["affected_hosts"]) >= 1
    assert len(engine.hunt_executions) == initial_hunts + 1


def test_execute_hunt_invalid_hypothesis():
    """Verifies that an unknown hypothesis ID raises KeyError."""
    engine = ThreatHuntingEngine()
    with pytest.raises(KeyError):
        engine.execute_hunt(hypothesis_id="HYP-UNKNOWN-999")


def test_generate_sigma_rule():
    """Verifies autonomous synthesis of valid Sigma YAML specification rule."""
    engine = ThreatHuntingEngine()
    rule = engine.generate_sigma_rule(
        hypothesis_id="HYP-002",
        title="Custom Sigma: Living-off-the-Land Certutil",
        severity="critical",
    )

    assert rule["format"] == RuleFormat.SIGMA_YAML.value
    assert rule["status"] == RuleStatus.VALIDATED.value
    assert rule["severity"] == "critical"
    assert rule["mitre_technique"] == "T1059.001"

    # Verify YAML content structure
    content = rule["content"]
    assert "title: Custom Sigma: Living-off-the-Land Certutil" in content
    assert "status: experimental" in content
    assert "logsource:" in content
    assert "category: process_creation" in content
    assert "detection:" in content
    assert "condition: selection" in content
    assert "level: critical" in content
    assert rule["id"] in engine.rules


def test_generate_yara_rule():
    """Verifies autonomous synthesis of valid YARA pattern matching rule."""
    engine = ThreatHuntingEngine()
    rule = engine.generate_yara_rule(
        hypothesis_id="HYP-003",
        rule_name="Hunt_LSASS_Memory_Infiltrator",
    )

    assert rule["format"] == RuleFormat.YARA.value
    assert rule["status"] == RuleStatus.VALIDATED.value
    assert rule["mitre_technique"] == "T1003.001"

    content = rule["content"]
    assert "rule Hunt_LSASS_Memory_Infiltrator {" in content
    assert "meta:" in content
    assert "strings:" in content
    assert "condition:" in content
    assert "any of them" in content
    assert rule["id"] in engine.rules


def test_deploy_rule_workflow():
    """Verifies deploying a synthesized detection rule directly to detection nodes."""
    engine = ThreatHuntingEngine()
    # Create rule
    rule = engine.generate_sigma_rule(hypothesis_id="HYP-001")
    assert rule["status"] == RuleStatus.VALIDATED.value
    assert rule["deployed_at"] is None

    # Deploy rule
    deployed = engine.deploy_rule(rule["id"])
    assert deployed["status"] == RuleStatus.DEPLOYED_ACTIVE.value
    assert deployed["deployed_at"] is not None

    # Invalid rule deploy raises KeyError
    with pytest.raises(KeyError):
        engine.deploy_rule("invalid-rule-id-404")


def test_threathunting_metrics():
    """Verifies aggregated threat hunting operational KPIs."""
    engine = ThreatHuntingEngine()
    engine.execute_hunt(hypothesis_id="HYP-001")
    metrics = engine.get_metrics()

    assert metrics["total_hypotheses"] >= 5
    assert metrics["total_hunts_executed"] >= 1
    assert metrics["hypothesis_validation_rate"] > 0.0
    assert metrics["total_detection_rules"] >= 2
    assert metrics["deployed_active_rules"] >= 2
    assert metrics["sigma_rules_count"] >= 1
    assert metrics["yara_rules_count"] >= 1
    assert metrics["mean_hunt_dwell_reduction_percent"] > 50.0

