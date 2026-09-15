# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Common Vulnerabilities and Exposures (CVE) & CVSS Mapping Service."""

import os
import sys
from typing import List, Dict, Optional, Any

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.threat_intel.models import CVEMatch, ThreatSeverity


# Curated high-impact CVE database keyed by destination port and protocol signatures
_KNOWLEDGE_BASE_CVES: List[CVEMatch] = [
    CVEMatch(
        cve_id="CVE-2017-0144",
        cvss_score=9.8,
        severity=ThreatSeverity.CRITICAL,
        description="EternalBlue: Remote Code Execution flaw in Microsoft Server Message Block 1.0 (SMBv1) protocol handling",
        affected_service="SMBv1",
        port=445,
        exploit_available=True,
        remediation="Disable SMBv1 and apply Microsoft security bulletin MS17-010",
    ),
    CVEMatch(
        cve_id="CVE-2020-0796",
        cvss_score=10.0,
        severity=ThreatSeverity.CRITICAL,
        description="SMBGhost: Pre-authentication buffer overflow in SMBv3 decompression routine",
        affected_service="SMBv3",
        port=445,
        exploit_available=True,
        remediation="Apply Microsoft security patch KB4551762 or disable SMBv3 compression",
    ),
    CVEMatch(
        cve_id="CVE-2019-0708",
        cvss_score=9.8,
        severity=ThreatSeverity.CRITICAL,
        description="BlueKeep: Pre-authentication remote code execution in Remote Desktop Protocol (RDP)",
        affected_service="RDP",
        port=3389,
        exploit_available=True,
        remediation="Enable Network Level Authentication (NLA) and apply KB4499175 patch",
    ),
    CVEMatch(
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        severity=ThreatSeverity.CRITICAL,
        description="Log4Shell: JNDI lookup injection in Apache Log4j 2 allowing arbitrary code execution",
        affected_service="HTTP/LDAP",
        port=8080,
        exploit_available=True,
        remediation="Upgrade Apache Log4j to >= 2.17.1 or set log4j2.formatMsgNoLookups=true",
    ),
    CVEMatch(
        cve_id="CVE-2022-22965",
        cvss_score=9.8,
        severity=ThreatSeverity.CRITICAL,
        description="Spring4Shell: Remote code execution in Spring Framework via data binding parameter pollution",
        affected_service="Spring HTTP",
        port=8080,
        exploit_available=True,
        remediation="Upgrade Spring Framework to version >= 5.3.18 or >= 5.2.20",
    ),
    CVEMatch(
        cve_id="CVE-2020-1472",
        cvss_score=10.0,
        severity=ThreatSeverity.CRITICAL,
        description="Zerologon: Netlogon cryptographic authentication bypass allowing domain controller takeover",
        affected_service="Kerberos / Netlogon",
        port=88,
        exploit_available=True,
        remediation="Enforce secure RPC communication with Netlogon protocol on domain controllers",
    ),
    CVEMatch(
        cve_id="CVE-2024-6387",
        cvss_score=8.1,
        severity=ThreatSeverity.HIGH,
        description="regreSSHion: Signal handler race condition in OpenSSH's server (sshd) on glibc Linux systems",
        affected_service="SSH",
        port=22,
        exploit_available=True,
        remediation="Upgrade OpenSSH to version >= 9.8p1 or set LoginGraceTime to 0 in sshd_config",
    ),
    CVEMatch(
        cve_id="CVE-2021-34473",
        cvss_score=9.8,
        severity=ThreatSeverity.CRITICAL,
        description="ProxyShell: Pre-authentication path confusion vulnerability in Microsoft Exchange Client Access Service",
        affected_service="Microsoft Exchange",
        port=443,
        exploit_available=True,
        remediation="Apply Microsoft Exchange cumulative security update KB5001779",
    ),
    CVEMatch(
        cve_id="CVE-2020-1350",
        cvss_score=10.0,
        severity=ThreatSeverity.CRITICAL,
        description="SIGRed: Wormable heap-based buffer overflow in Windows DNS Server parsing malicious SIG queries",
        affected_service="DNS",
        port=53,
        exploit_available=True,
        remediation="Apply KB4565503 or configure TcpReceivePacketSize registry workaround",
    ),
]


class CVEMatcher:
    """Matches network anomaly indicators and open ports to known high-impact CVEs."""

    def __init__(self):
        self._cves_by_port: Dict[int, List[CVEMatch]] = {}
        self._cves_by_id: Dict[str, CVEMatch] = {}

        for cve in _KNOWLEDGE_BASE_CVES:
            self._cves_by_id[cve.cve_id.upper()] = cve
            if cve.port:
                if cve.port not in self._cves_by_port:
                    self._cves_by_port[cve.port] = []
                self._cves_by_port[cve.port].append(cve)

    def match_by_port(self, port: int) -> List[CVEMatch]:
        """Returns CVEs associated with a destination port."""
        return list(self._cves_by_port.get(port, []))

    def match_by_id(self, cve_id: str) -> Optional[CVEMatch]:
        """Returns CVE match by CVE identifier."""
        return self._cves_by_id.get(cve_id.strip().upper())

    def match_context(
        self,
        port: Optional[int] = None,
        attack_category: Optional[str] = None,
        service: Optional[str] = None,
    ) -> List[CVEMatch]:
        """Correlates multiple observation dimensions (port, attack category, service) to potential CVEs."""
        matches: List[CVEMatch] = []
        seen_ids = set()

        if port and port in self._cves_by_port:
            for cve in self._cves_by_port[port]:
                if cve.cve_id not in seen_ids:
                    matches.append(cve)
                    seen_ids.add(cve.cve_id)

        # Context-based matching for specific attack classes
        if attack_category:
            cat_upper = attack_category.upper()
            if "EXPLOIT" in cat_upper or "COMMAND_INJECTION" in cat_upper:
                # Prioritize Log4Shell and Spring4Shell if web ports or not specified
                for cve_id in ["CVE-2021-44228", "CVE-2022-22965"]:
                    cve = self._cves_by_id.get(cve_id)
                    if cve and cve.cve_id not in seen_ids:
                        matches.append(cve)
                        seen_ids.add(cve.cve_id)

            elif "LATERAL_MOVEMENT" in cat_upper or "SMB" in cat_upper:
                for cve_id in ["CVE-2017-0144", "CVE-2020-1472"]:
                    cve = self._cves_by_id.get(cve_id)
                    if cve and cve.cve_id not in seen_ids:
                        matches.append(cve)
                        seen_ids.add(cve.cve_id)

        return matches

    def get_all_cves(self) -> List[CVEMatch]:
        """Returns entire database of mapped CVEs."""
        return list(_KNOWLEDGE_BASE_CVES)


cve_matcher = CVEMatcher()

