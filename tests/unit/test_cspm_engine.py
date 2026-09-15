# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Unit tests for Autonomous Cloud Security Posture Management (CSPM) & IaC Guard Engine."""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.cspm.engine import (
    CspmEngine,
    CloudProvider,
    FindingStatus,
    cspm_engine,
)


def test_default_policies_loaded():
    """Verifies curated multi-cloud CIS benchmarks and compliance controls are loaded."""
    engine = CspmEngine()
    policies = engine.get_policies()
    assert len(policies) >= 6

    policy_ids = {p["policy_id"] for p in policies}
    assert "CIS-AWS-2.1.5" in policy_ids
    assert "CIS-K8S-5.2.1" in policy_ids
    assert "CIS-AZ-3.1" in policy_ids
    assert "CIS-GCP-1.4" in policy_ids

    # Verify AWS S3 policy details
    s3_pol = next(p for p in policies if p["policy_id"] == "CIS-AWS-2.1.5")
    assert s3_pol["provider"] == CloudProvider.AWS.value
    assert s3_pol["severity"] == "CRITICAL"
    assert "public_access_block" in s3_pol["remediation_guide"]


def test_default_findings_loaded():
    """Verifies pre-seeded cloud misconfigurations across AWS, Azure, GCP, and Kubernetes."""
    engine = CspmEngine()
    findings = engine.get_findings()
    assert len(findings) >= 6

    # Verify provider filtering
    aws_findings = engine.get_findings(provider="AWS")
    assert len(aws_findings) >= 2
    assert all(f["provider"] == "AWS" for f in aws_findings)

    k8s_findings = engine.get_findings(provider="KUBERNETES")
    assert len(k8s_findings) >= 2
    assert all(f["provider"] == "KUBERNETES" for f in k8s_findings)

    # Verify severity filtering
    crit_findings = engine.get_findings(severity="CRITICAL")
    assert len(crit_findings) >= 2
    assert all(f["severity"] == "CRITICAL" for f in crit_findings)


def test_get_finding_patch_content():
    """Verifies synthesized Infrastructure-as-Code (IaC) patch contains valid unified diff."""
    engine = CspmEngine()
    patch = engine.get_finding_patch("FIND-AWS-001")

    assert patch["finding_id"] == "FIND-AWS-001"
    assert patch["iac_format"] == "TERRAFORM_HCL"
    assert "aws_s3_bucket_public_access_block" in patch["unified_diff"]
    assert "block_public_acls" in patch["synthesized_code"]
    assert patch["pull_request_branch"].startswith("fix/iac-cspm-")


def test_remediate_finding_generates_pr():
    """Verifies remediating a cloud finding updates status and creates a verified Git PR."""
    engine = CspmEngine()
    initial_metrics = engine.get_metrics()
    assert initial_metrics["remediated_findings_count"] == 0

    result = engine.remediate_finding("FIND-AWS-001")
    assert result["finding_id"] == "FIND-AWS-001"
    assert result["status"] == FindingStatus.REMEDIATED.value
    assert result["pull_request_id"].startswith("PR-CSPM-")
    assert result["new_compliance_score"] > initial_metrics["overall_cis_compliance_percent"]

    # Verify finding object updated in memory
    f = engine.get_finding("FIND-AWS-001")
    assert f["status"] == FindingStatus.REMEDIATED.value
    assert f["remediated_at"] is not None

    updated_metrics = engine.get_metrics()
    assert updated_metrics["remediated_findings_count"] == 1
    assert updated_metrics["active_findings_count"] == initial_metrics["active_findings_count"] - 1


def test_remediate_unknown_finding():
    """Verifies KeyError is raised for invalid finding IDs."""
    engine = CspmEngine()
    with pytest.raises(KeyError):
        engine.remediate_finding("FIND-DOES-NOT-EXIST")


def test_reset_findings():
    """Verifies resetting findings restores baseline state and clears PR IDs."""
    engine = CspmEngine()
    engine.remediate_finding("FIND-AWS-001")
    assert engine.get_metrics()["remediated_findings_count"] == 1

    engine.reset_findings()
    metrics = engine.get_metrics()
    assert metrics["remediated_findings_count"] == 0
    assert metrics["active_findings_count"] == metrics["total_findings_count"]
    assert all(f["status"] == FindingStatus.OPEN.value for f in engine.findings.values())


def test_cspm_metrics_calculation():
    """Verifies multi-cloud compliance and provider-level scores."""
    engine = CspmEngine()
    metrics = engine.get_metrics()

    assert metrics["overall_cis_compliance_percent"] >= 80.0
    assert metrics["total_cloud_resources_scanned"] > 100
    assert metrics["total_findings_count"] >= 6
    assert "AWS" in metrics["compliance_by_provider"]
    assert "KUBERNETES" in metrics["compliance_by_provider"]
    assert "AZURE" in metrics["compliance_by_provider"]
    assert "GCP" in metrics["compliance_by_provider"]

