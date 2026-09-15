# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Unit tests for Software Supply Chain Security (SCA) & Autonomous SBOM Governance Engine."""

import pytest
from backend.app.sca.engine import (
    ScaEngine,
    PackageEcosystem,
    VulnerabilitySeverity,
    ReachabilityStatus,
    VulnerabilityStatus,
    LicenseRiskLevel,
    SupplyChainThreatType,
)


@pytest.fixture
def sca_instance():
    """Returns a fresh isolated instance of ScaEngine for testing."""
    return ScaEngine()


def test_sca_engine_initialization(sca_instance):
    """Verifies that ScaEngine seeds SBOMs, components, CVEs, threats, and licenses."""
    metrics = sca_instance.get_metrics()
    assert metrics["health_score"] > 0
    assert metrics["total_sboms"] == 3
    assert metrics["total_components"] >= 18
    assert metrics["open_vulnerabilities"] >= 5
    assert metrics["cisa_kev_active"] >= 2
    assert metrics["direct_reachable_active"] >= 2
    assert metrics["active_threats_count"] >= 3
    assert metrics["license_violations_count"] >= 1


def test_get_sboms(sca_instance):
    """Verifies retrieval of registered Software Bill of Materials documents."""
    sboms = sca_instance.get_sboms()
    assert len(sboms) == 3
    sbom_ids = [s["sbom_id"] for s in sboms]
    assert "SBOM-CORE-API" in sbom_ids
    assert "SBOM-WEB-UI" in sbom_ids
    assert "SBOM-INGRESS-GW" in sbom_ids


def test_export_cyclonedx_standard(sca_instance):
    """Verifies generation of standardized CycloneDX v1.5 JSON SBOM."""
    doc = sca_instance.export_cyclonedx("SBOM-CORE-API")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert "serialNumber" in doc
    assert doc["metadata"]["component"]["name"] == "cyberdefense-core-api"
    assert len(doc["components"]) > 0

    first_comp = doc["components"][0]
    assert "purl" in first_comp
    assert first_comp["purl"].startswith("pkg:pypi/")
    assert "licenses" in first_comp

    # Non-existent SBOM raises KeyError
    with pytest.raises(KeyError):
        sca_instance.export_cyclonedx("NON-EXISTENT-SBOM")


def test_get_components_filtering(sca_instance):
    """Verifies component retrieval with ecosystem and direct/transitive filtering."""
    pypi_comps = sca_instance.get_components(ecosystem="pypi")
    assert len(pypi_comps) > 0
    for c in pypi_comps:
        assert c["ecosystem"] == PackageEcosystem.PYPI.value

    npm_direct = sca_instance.get_components(ecosystem="npm", is_direct=True)
    assert len(npm_direct) > 0
    for c in npm_direct:
        assert c["ecosystem"] == PackageEcosystem.NPM.value
        assert c["is_direct"] is True


def test_get_vulnerabilities_filtering(sca_instance):
    """Verifies vulnerability querying with severity, KEV, and reachability filters."""
    high_vulns = sca_instance.get_vulnerabilities(severity="HIGH")
    assert len(high_vulns) > 0
    for v in high_vulns:
        assert v["severity"] == VulnerabilitySeverity.HIGH.value

    kev_vulns = sca_instance.get_vulnerabilities(cisa_kev_only=True)
    assert len(kev_vulns) >= 2
    for v in kev_vulns:
        assert v["cisa_kev"] is True

    direct_vulns = sca_instance.get_vulnerabilities(reachability=ReachabilityStatus.DIRECT_EXECUTION_PATH.value)
    assert len(direct_vulns) >= 2
    for v in direct_vulns:
        assert v["reachability"] == ReachabilityStatus.DIRECT_EXECUTION_PATH.value


def test_threat_and_license_detection(sca_instance):
    """Verifies detection of typosquatting, dependency confusion, and AGPL copyleft violations."""
    threats = sca_instance.get_threats()
    assert len(threats) >= 3
    types = [t["type"] for t in threats]
    assert SupplyChainThreatType.TYPOSQUATTING.value in types
    assert SupplyChainThreatType.DEPENDENCY_CONFUSION.value in types
    assert SupplyChainThreatType.MALICIOUS_INSTALL_SCRIPT.value in types

    licenses = sca_instance.get_license_risks()
    assert len(licenses) >= 1
    assert licenses[0]["license"] == "AGPL-3.0"
    assert licenses[0]["risk_level"] == LicenseRiskLevel.HIGH_RISK.value


def test_remediation_patch_and_execution(sca_instance):
    """Verifies autonomous unified diff synthesis and one-click remediation."""
    patch = sca_instance.get_remediation_patch("VULN-001")
    assert patch["cve_id"] == "CVE-2023-44487"
    assert "unified_diff" in patch
    assert "google.golang.org/grpc v1.59.0" in patch["unified_diff"]
    assert "git_branch" in patch

    initial_metrics = sca_instance.get_metrics()
    result = sca_instance.remediate_vulnerability("VULN-001")

    assert result["status"] == "SUCCESS"
    assert result["vulnerability_status"] == VulnerabilityStatus.REMEDIATED.value
    assert result["new_health_score"] >= initial_metrics["health_score"]
    assert "audit_trail_id" in result

    # Check that vulnerability is now REMEDIATED
    vuln = sca_instance.vulnerabilities["VULN-001"]
    assert vuln["status"] == VulnerabilityStatus.REMEDIATED.value

    # Check that component version was updated
    comp = sca_instance.components[vuln["component_id"]]
    assert comp["version"] == vuln["fixed_version"]

    # Invalid ID checks
    with pytest.raises(KeyError):
        sca_instance.get_remediation_patch("INVALID-VULN")

    with pytest.raises(KeyError):
        sca_instance.remediate_vulnerability("INVALID-VULN")

