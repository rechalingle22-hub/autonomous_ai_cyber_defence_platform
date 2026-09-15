# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Attack Surface Management (ASM) & Risk-Based Vulnerability Prioritization Engine."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.asm.engine import (
    AttackSurfaceEngine,
    AssetCriticalityTier,
    ExposureLevel,
    VulnerabilityPriority,
    VulnerabilityStatus,
    asm_engine,
)


def test_contextual_risk_score_calculation():
    """Verifies formula: CVSS*3.5 + EPSS*40 + Criticality + Exposure + Exploit - ZT."""
    engine = AttackSurfaceEngine()

    # Case 1: P0 Critical Emergency (CVSS 10.0, EPSS 0.95, Tier 1, Internet Facing, Exploit, No ZT)
    # 35.0 + 38.0 + 20.0 + 15.0 + 10.0 = 118.0 -> capped at 100.0
    result_p0 = engine.calculate_contextual_risk(
        cvss_score=10.0,
        epss_probability=0.95,
        criticality=AssetCriticalityTier.TIER_1_MISSION_CRITICAL.value,
        exposure=ExposureLevel.INTERNET_FACING.value,
        has_zero_trust_control=False,
        has_known_exploit=True,
    )
    assert result_p0["contextual_risk_score"] == 100.0
    assert result_p0["priority"] == VulnerabilityPriority.P0_CRITICAL.value
    assert result_p0["sla_hours"] == 24
    assert result_p0["score_breakdown"]["cvss_component"] == 35.0
    assert result_p0["score_breakdown"]["epss_component"] == 38.0
    assert result_p0["score_breakdown"]["criticality_bonus"] == 20.0
    assert result_p0["score_breakdown"]["exposure_bonus"] == 15.0
    assert result_p0["score_breakdown"]["exploit_bonus"] == 10.0
    assert result_p0["score_breakdown"]["zero_trust_discount"] == 0.0

    # Case 2: Compensating Zero-Trust Discount
    # CVSS 8.0 (28.0) + EPSS 0.40 (16.0) + Tier 2 (10.0) + DMZ (10.0) - ZT (15.0) = 49.0
    result_zt = engine.calculate_contextual_risk(
        cvss_score=8.0,
        epss_probability=0.40,
        criticality=AssetCriticalityTier.TIER_2_CORE_OPERATIONAL.value,
        exposure=ExposureLevel.DMZ.value,
        has_zero_trust_control=True,
        has_known_exploit=False,
    )
    assert result_zt["contextual_risk_score"] == 49.0
    assert result_zt["priority"] == VulnerabilityPriority.P2_MEDIUM.value
    assert result_zt["sla_hours"] == 720
    assert result_zt["score_breakdown"]["zero_trust_discount"] == 15.0


def test_asset_discovery_and_inventory():
    """Verifies automated scanning discovers new surface assets and records scan history."""
    engine = AttackSurfaceEngine()
    initial_assets = len(engine.assets)
    initial_scans = len(engine.scan_history)

    updated_assets = engine.discover_assets(
        subnet_range="198.51.100.0/24",
        scan_intensity="COMPREHENSIVE",
    )

    assert len(updated_assets) == initial_assets + 1
    assert len(engine.scan_history) == initial_scans + 1
    latest_scan = engine.scan_history[-1]
    assert latest_scan["subnet_range"] == "198.51.100.0/24"
    assert latest_scan["assets_discovered"] == 1


def test_vulnerability_prioritization_sorting():
    """Verifies that prioritize_vulnerabilities returns CVEs ordered by Contextual Risk Score descending."""
    engine = AttackSurfaceEngine()
    prioritized = engine.prioritize_vulnerabilities()

    assert len(prioritized) >= 5
    # Ensure descending order
    scores = [v["contextual_risk_score"] for v in prioritized]
    assert scores == sorted(scores, reverse=True)

    # Top CVE should be highest risk
    top_vuln = prioritized[0]
    assert top_vuln["priority"] in (VulnerabilityPriority.P0_CRITICAL.value, VulnerabilityPriority.P1_HIGH.value)
    assert "sla_deadline" in top_vuln


def test_vulnerability_remediation_workflow():
    """Verifies remediating a CVE updates its status and reduces the host asset's active vuln count."""
    engine = AttackSurfaceEngine()
    cve_id = "CVE-2024-3400"
    target_vuln = engine.vulnerabilities[cve_id]
    asset_id = target_vuln["asset_id"]
    initial_asset_vulns = engine.assets[asset_id]["active_vulnerabilities_count"]

    remediated = engine.remediate_vulnerability(
        cve_id=cve_id,
        resolution_notes="WAF virtual patch rule ID-9941 deployed across edge Envoy proxies",
        action="APPLY_VIRTUAL_PATCH",
    )

    assert remediated["status"] == VulnerabilityStatus.REMEDIATED.value
    assert remediated["resolution_notes"] == "WAF virtual patch rule ID-9941 deployed across edge Envoy proxies"
    assert remediated["remediated_at"] is not None
    assert engine.assets[asset_id]["active_vulnerabilities_count"] == max(0, initial_asset_vulns - 1)


def test_asm_metrics_aggregation():
    """Verifies attack surface exposure score and operational RBVM KPIs."""
    engine = AttackSurfaceEngine()
    metrics = engine.get_asm_metrics()

    assert metrics["total_assets"] >= 5
    assert metrics["internet_facing_assets"] >= 2
    assert metrics["total_vulnerabilities"] >= 5
    assert metrics["attack_surface_exposure_score"] > 0.0
    assert metrics["sla_compliance_rate"] >= 90.0
    assert metrics["p0_critical_count"] >= 1

