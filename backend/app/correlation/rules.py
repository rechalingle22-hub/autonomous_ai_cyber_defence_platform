# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""MITRE ATT&CK correlation rules, entity matching heuristics, and risk scoring."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import math
from typing import Dict, Any, Optional, Tuple, Set  # type: ignore

try:
    from ..models.incident import AttackStage  # type: ignore
    from ..models.alert import AlertSeverity  # type: ignore
except (ImportError, ValueError):
    from backend.app.models.incident import AttackStage  # type: ignore
    from backend.app.models.alert import AlertSeverity  # type: ignore

# Stage progression ordering and weights (0-100)
STAGE_WEIGHTS: Dict[AttackStage, float] = {
    AttackStage.RECONNAISSANCE: 15.0,
    AttackStage.INITIAL_ACCESS: 30.0,
    AttackStage.EXECUTION: 45.0,
    AttackStage.PERSISTENCE: 55.0,
    AttackStage.PRIVILEGE_ESCALATION: 65.0,
    AttackStage.LATERAL_MOVEMENT: 75.0,
    AttackStage.COLLECTION: 80.0,
    AttackStage.EXFILTRATION: 90.0,
    AttackStage.IMPACT: 100.0,
}

# Attack type to MITRE Stage & Technique mapping
ATTACK_TYPE_MAPPING: Dict[str, Tuple[AttackStage, str, str]] = {
    "PORT_SCAN": (AttackStage.RECONNAISSANCE, "T1046", "Reconnaissance"),
    "SCAN": (AttackStage.RECONNAISSANCE, "T1046", "Reconnaissance"),
    "RECON": (AttackStage.RECONNAISSANCE, "T1595", "Reconnaissance"),
    "PING_SWEEP": (AttackStage.RECONNAISSANCE, "T1018", "Reconnaissance"),
    "NETWORK_DISCOVERY": (AttackStage.RECONNAISSANCE, "T1046", "Reconnaissance"),
    "BRUTE_FORCE": (AttackStage.INITIAL_ACCESS, "T1110", "Credential Access"),
    "SSH_BRUTE_FORCE": (AttackStage.INITIAL_ACCESS, "T1110.001", "Credential Access"),
    "PASSWORD_SPRAY": (AttackStage.INITIAL_ACCESS, "T1110.003", "Credential Access"),
    "AUTH_ANOMALY": (AttackStage.INITIAL_ACCESS, "T1078", "Initial Access"),
    "CREDENTIAL_ACCESS": (AttackStage.INITIAL_ACCESS, "T1110", "Credential Access"),
    "COMMAND_INJECTION": (AttackStage.EXECUTION, "T1059", "Execution"),
    "EXPLOIT": (AttackStage.EXECUTION, "T1203", "Execution"),
    "CODE_EXECUTION": (AttackStage.EXECUTION, "T1059", "Execution"),
    "WEB_ATTACK": (AttackStage.EXECUTION, "T1190", "Initial Access"),
    "SQL_INJECTION": (AttackStage.EXECUTION, "T1190", "Execution"),
    "PERSISTENCE": (AttackStage.PERSISTENCE, "T1053", "Persistence"),
    "SCHEDULED_TASK": (AttackStage.PERSISTENCE, "T1053.005", "Persistence"),
    "CRON_MODIFICATION": (AttackStage.PERSISTENCE, "T1053.003", "Persistence"),
    "REGISTRY_MOD": (AttackStage.PERSISTENCE, "T1547", "Persistence"),
    "PRIVILEGE_ESCALATION": (AttackStage.PRIVILEGE_ESCALATION, "T1068", "Privilege Escalation"),
    "SUDO_ABUSE": (AttackStage.PRIVILEGE_ESCALATION, "T1548.003", "Privilege Escalation"),
    "TOKEN_IMPERSONATION": (AttackStage.PRIVILEGE_ESCALATION, "T1134", "Privilege Escalation"),
    "LATERAL_MOVEMENT": (AttackStage.LATERAL_MOVEMENT, "T1021", "Lateral Movement"),
    "PASS_THE_HASH": (AttackStage.LATERAL_MOVEMENT, "T1550.002", "Lateral Movement"),
    "REMOTE_SERVICES": (AttackStage.LATERAL_MOVEMENT, "T1021.001", "Lateral Movement"),
    "SMB_EXEC": (AttackStage.LATERAL_MOVEMENT, "T1021.002", "Lateral Movement"),
    "DATA_STAGING": (AttackStage.COLLECTION, "T1074", "Collection"),
    "COLLECTION": (AttackStage.COLLECTION, "T1005", "Collection"),
    "KEYLOGGING": (AttackStage.COLLECTION, "T1056.001", "Collection"),
    "DATA_EXFIL": (AttackStage.EXFILTRATION, "T1048", "Exfiltration"),
    "EXFILTRATION": (AttackStage.EXFILTRATION, "T1048", "Exfiltration"),
    "DNS_TUNNELING": (AttackStage.EXFILTRATION, "T1071.004", "Command and Control"),
    "DATA_EGRESS": (AttackStage.EXFILTRATION, "T1048", "Exfiltration"),
    "C2_COMMUNICATION": (AttackStage.EXFILTRATION, "T1071", "Command and Control"),
    "RANSOMWARE": (AttackStage.IMPACT, "T1486", "Impact"),
    "DATA_ENCRYPTION": (AttackStage.IMPACT, "T1486", "Impact"),
    "WIPER": (AttackStage.IMPACT, "T1561", "Impact"),
    "DOS": (AttackStage.IMPACT, "T1499", "Impact"),
    "DDOS": (AttackStage.IMPACT, "T1498", "Impact"),
    "SERVICE_STOP": (AttackStage.IMPACT, "T1489", "Impact"),
}


class CorrelationRules:
    """Deterministic MITRE ATT&CK correlation heuristics, entity matching, and composite risk scoring."""

    @staticmethod
    def map_attack_stage(attack_type: Optional[str]) -> Tuple[AttackStage, str, str]:
        """Resolves attack type string to AttackStage, MITRE technique ID, and tactic name."""
        if not attack_type:
            return AttackStage.INITIAL_ACCESS, "T1190", "Initial Access"
        
        normalized = attack_type.strip().upper().replace(" ", "_").replace("-", "_")
        if normalized in ATTACK_TYPE_MAPPING:
            return ATTACK_TYPE_MAPPING[normalized]

        for key in sorted(ATTACK_TYPE_MAPPING.keys(), key=len, reverse=True):
            if key in normalized or normalized in key:
                return ATTACK_TYPE_MAPPING[key]
        
        return AttackStage.INITIAL_ACCESS, "T1190", "Initial Access"

    @staticmethod
    def get_stage_weight(stage: AttackStage) -> float:
        """Returns the numerical severity weight of an AttackStage."""
        return STAGE_WEIGHTS.get(stage, 25.0)

    @staticmethod
    def evaluate_highest_stage(stages: list[AttackStage]) -> AttackStage:
        """Selects the highest attack stage in kill chain progression."""
        if not stages:
            return AttackStage.INITIAL_ACCESS
        return max(stages, key=lambda s: STAGE_WEIGHTS.get(s, 0.0))

    @staticmethod
    def match_entities(
        alert_entities: Dict[str, Any],
        incident_entities: Dict[str, Set[str]],
    ) -> Tuple[bool, Optional[str]]:
        """Determines if an alert matches an incident candidate based on multi-entity heuristics.
        
        Returns:
            (is_matched, match_reason)
        """
        src_ip = alert_entities.get("source_ip")
        dst_ip = alert_entities.get("destination_ip")
        user_id = alert_entities.get("user_id")
        asset_id = alert_entities.get("asset_id")

        inc_sources = incident_entities.get("source_ips", set())
        inc_destinations = incident_entities.get("destination_ips", set())
        inc_users = incident_entities.get("user_ids", set())
        inc_assets = incident_entities.get("asset_ids", set())

        # 1. Direct source IP match
        if src_ip and src_ip in inc_sources:
            return True, "shared_source_ip"

        # 2. Direct destination IP match (targeting the same target)
        if dst_ip and dst_ip in inc_destinations:
            return True, "shared_destination_ip"

        # 3. Lateral movement pivot: alert source IP was previously an incident destination IP
        if src_ip and src_ip in inc_destinations:
            return True, "lateral_movement_pivot_from_target"

        # 4. Reverse pivot: alert destination matches previous attacker source IP
        if dst_ip and dst_ip in inc_sources:
            return True, "lateral_movement_pivot_to_attacker"

        # 5. Shared compromised user
        if user_id and user_id in inc_users:
            return True, "shared_compromised_user"

        # 6. Shared compromised asset
        if asset_id and asset_id in inc_assets:
            return True, "shared_monitored_asset"

        return False, None

    @staticmethod
    def calculate_composite_risk_score(
        confidences: list[float],
        anomaly_scores: list[float],
        highest_stage: AttackStage,
    ) -> float:
        """Calculates dynamic composite risk score (0.0 to 100.0).
        
        Formula:
            Score = min(100.0, w_conf * C_avg + w_anomaly * A_max + w_stage * S_stage + volume_boost)
        """
        if not confidences:
            c_avg = 50.0
        else:
            # Normalize confidence if on 0-1 scale to 0-100
            norm_conf = [c * 100.0 if c <= 1.0 else c for c in confidences]
            c_avg = sum(norm_conf) / len(norm_conf)

        if not anomaly_scores:
            a_max = 50.0
        else:
            norm_anom = [a * 100.0 if a <= 1.0 else a for a in anomaly_scores]
            a_max = max(norm_anom)

        stage_weight = STAGE_WEIGHTS.get(highest_stage, 25.0)

        # Logarithmic volume boost recognizing multi-alert coordinated clusters
        n = max(1, len(confidences))
        volume_boost = min(15.0, 5.0 * math.log2(n + 1))

        # Weighted combination: 35% Confidence + 35% Peak Anomaly + 20% Stage Progression + Volume
        raw_score = (0.35 * c_avg) + (0.35 * a_max) + (0.20 * stage_weight) + volume_boost
        return round(max(0.0, min(100.0, raw_score)), 2)

    @staticmethod
    def determine_severity(risk_score: float) -> AlertSeverity:
        """Maps composite risk score to standard AlertSeverity."""
        if risk_score >= 80.0:
            return AlertSeverity.CRITICAL
        if risk_score >= 60.0:
            return AlertSeverity.HIGH
        if risk_score >= 35.0:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW
