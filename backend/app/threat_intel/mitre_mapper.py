# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""MITRE ATT&CK Threat Actor Attribution & TTP Mapping Engine."""

import os
import sys
from typing import List, Dict, Optional, Any

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.threat_intel.models import ThreatActorProfile


_THREAT_ACTORS: List[ThreatActorProfile] = [
    ThreatActorProfile(
        actor_name="APT28",
        aliases=["Fancy Bear", "STRONTIUM", "Sednit", "Sofacy", "Pawn Storm"],
        country_of_origin="Russia (GRU)",
        primary_motivation="ESPIONAGE",
        target_sectors=["Government", "Defense", "NATO Entities", "Aviation", "Energy"],
        known_ttp_ids=["T1190", "T1059", "T1078", "T1046", "T1048", "T1566"],
        signature_tools=["X-Agent", "Zebrocy", "Sofacy", "CHOPSTICK"],
    ),
    ThreatActorProfile(
        actor_name="APT29",
        aliases=["Cozy Bear", "NOBELIUM", "Midnight Blizzard", "The Dukes"],
        country_of_origin="Russia (SVR)",
        primary_motivation="ESPIONAGE",
        target_sectors=["Government", "Diplomatic", "Think Tanks", "Cloud Providers", "Technology"],
        known_ttp_ids=["T1195", "T1078", "T1071", "T1048", "T1027", "T1110"],
        signature_tools=["Cobalt Strike", "WellMess", "EnvyScout", "GoldMax"],
    ),
    ThreatActorProfile(
        actor_name="FIN7",
        aliases=["Carbanak", "Navigator Group", "ELBRUS"],
        country_of_origin="Eastern Europe / International",
        primary_motivation="FINANCIAL",
        target_sectors=["Retail", "Hospitality", "Banking", "Payment Processors"],
        known_ttp_ids=["T1566", "T1059", "T1055", "T1041", "T1078", "T1021"],
        signature_tools=["Carbanak", "GRIFFON", "LNK Stagers", "SQLRat"],
    ),
    ThreatActorProfile(
        actor_name="Lazarus Group",
        aliases=["HIDDEN COBRA", "Guardians of Peace", "ZINC", "Labyrinth Chollima"],
        country_of_origin="North Korea (RGB)",
        primary_motivation="FINANCIAL_AND_SABOTAGE",
        target_sectors=["Cryptocurrency", "Defense", "Financial Institutions", "Media"],
        known_ttp_ids=["T1566", "T1190", "T1059", "T1486", "T1048", "T1505"],
        signature_tools=["WannaCry", "AppleJeus", "Fallchill", "Brambul", "Volgmer"],
    ),
    ThreatActorProfile(
        actor_name="Wizard Spider",
        aliases=["UNC1878", "Grim Spider"],
        country_of_origin="Eastern Europe",
        primary_motivation="FINANCIAL",
        target_sectors=["Healthcare", "Education", "Critical Infrastructure", "Municipalities"],
        known_ttp_ids=["T1486", "T1059", "T1021", "T1078", "T1048", "T1068"],
        signature_tools=["LockBit", "Conti", "TrickBot", "Ryuk", "BazarLoader"],
    ),
    ThreatActorProfile(
        actor_name="Sandworm",
        aliases=["TeleBots", "Voodoo Bear", "IRIDIUM", "ELECTRUM"],
        country_of_origin="Russia (GRU)",
        primary_motivation="SABOTAGE",
        target_sectors=["Power Grid", "Industrial Utilities", "Government", "Transport"],
        known_ttp_ids=["T1190", "T1059", "T1498", "T1485", "T1562", "T1078"],
        signature_tools=["BlackEnergy", "Industroyer", "HermeticWiper", "CaddyWiper"],
    ),
    ThreatActorProfile(
        actor_name="Volt Typhoon",
        aliases=["BRONZE SILHOUETTE", "Vanguard Panda"],
        country_of_origin="China (State-Sponsored)",
        primary_motivation="PREPOSITIONING_AND_ESPIONAGE",
        target_sectors=["Critical Infrastructure", "Telecommunications", "Maritime", "Government"],
        known_ttp_ids=["T1078", "T1190", "T1046", "T1071", "T1059", "T1049"],
        signature_tools=["Living-off-the-Land (LotL)", "Fast Reverse Proxy", "Custom Web Shells"],
    ),
]

_TECHNIQUE_TO_TACTIC = {
    "T1566": "Initial Access",
    "T1190": "Initial Access",
    "T1195": "Initial Access",
    "T1059": "Execution",
    "T1055": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1562": "Defense Evasion",
    "T1505": "Persistence",
    "T1078": "Persistence / Privilege Escalation",
    "T1068": "Privilege Escalation",
    "T1110": "Credential Access",
    "T1046": "Discovery",
    "T1049": "Discovery",
    "T1021": "Lateral Movement",
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1071": "Command and Control",
    "T1486": "Impact",
    "T1485": "Impact",
    "T1498": "Impact",
}


class MITREMapper:
    """Attributes observed telemetry and technique signatures to adversary group profiles."""

    def __init__(self):
        self._actors_by_name: Dict[str, ThreatActorProfile] = {}
        self._actors_by_alias: Dict[str, ThreatActorProfile] = {}

        for profile in _THREAT_ACTORS:
            self._actors_by_name[profile.actor_name.upper()] = profile
            for alias in profile.aliases:
                self._actors_by_alias[alias.upper()] = profile

    def get_actor(self, identifier: str) -> Optional[ThreatActorProfile]:
        """Looks up an actor profile by primary name or known alias."""
        clean = identifier.strip().upper()
        if clean in self._actors_by_name:
            return self._actors_by_name[clean]
        return self._actors_by_alias.get(clean)

    def attribute_threat(
        self,
        actor_hint: Optional[str] = None,
        malware_family: Optional[str] = None,
        attack_category: Optional[str] = None,
        techniques: Optional[List[str]] = None,
    ) -> Optional[ThreatActorProfile]:
        """Heuristically attributes threats using multiple CTI dimensions."""
        if actor_hint:
            match = self.get_actor(actor_hint)
            if match:
                return match

        # Match by signature tools / malware family
        if malware_family:
            mf_upper = malware_family.upper()
            for profile in _THREAT_ACTORS:
                for tool in profile.signature_tools:
                    if tool.upper() in mf_upper or mf_upper in tool.upper():
                        return profile

        # Match by distinct attack taxonomy + technique combination
        if techniques:
            tech_set = set(t.upper() for t in techniques)
            best_profile = None
            max_matches = 0

            for profile in _THREAT_ACTORS:
                actor_techs = set(t.upper() for t in profile.known_ttp_ids)
                overlap = len(tech_set.intersection(actor_techs))
                if overlap > max_matches:
                    max_matches = overlap
                    best_profile = profile

            if max_matches >= 2:
                return best_profile

        # Fallback by known major campaign indicators
        if attack_category:
            cat_upper = attack_category.upper()
            if "RANSOMWARE" in cat_upper:
                return self.get_actor("Wizard Spider")
            elif "EXFILTRATION" in cat_upper:
                return self.get_actor("APT29")
            elif "BRUTE_FORCE" in cat_upper:
                return self.get_actor("APT28")

        return None

    def get_tactics_for_techniques(self, technique_ids: List[str]) -> List[str]:
        """Resolves MITRE ATT&CK tactic categories for technique IDs."""
        tactics = set()
        for t in technique_ids:
            tac = _TECHNIQUE_TO_TACTIC.get(t.upper())
            if tac:
                tactics.add(tac)
        return sorted(list(tactics))

    def list_all_actors(self) -> List[ThreatActorProfile]:
        """Returns list of all cataloged threat actor profiles."""
        return list(_THREAT_ACTORS)


mitre_mapper = MITREMapper()

