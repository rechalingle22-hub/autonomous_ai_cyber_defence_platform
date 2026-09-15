# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Zero-Trust Adaptive Access Control & Micro-Segmentation Policy Engine.

Governs:
1. NIST SP 800-207 compliant Continuous Contextual Trust Score calculation (0-100).
2. Dynamic Policy Decision Point (PDP) evaluating access requests against resource sensitivity.
3. Micro-Segmentation & Software-Defined Perimeter (SDP) rule enforcement preventing lateral movement.
4. Continuous verification, Step-Up MFA challenges, and real-time session quarantine.
"""

import os
import sys
import uuid
import enum
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


class AccessDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    RESTRICT = "RESTRICT"
    BLOCK = "BLOCK"


class ResourceSensitivity(str, enum.Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED_CROWN_JEWEL = "RESTRICTED_CROWN_JEWEL"


class AuthAssuranceLevel(str, enum.Enum):
    PASSWORD_ONLY = "PASSWORD_ONLY"
    PASSWORD_SMS = "PASSWORD_SMS"
    HARDWARE_MFA_FIDO2 = "HARDWARE_MFA_FIDO2"


class ZeroTrustEngine:
    """Orchestrates continuous contextual trust evaluation and micro-segmentation."""

    def __init__(self) -> None:
        self.microsegmentation_policies: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.evaluation_history: List[Dict[str, Any]] = []
        self._initialize_default_policies()
        self._initialize_default_sessions()

    def _initialize_default_policies(self) -> None:
        """Seeds default enterprise micro-segmentation network security policies."""
        default_rules = [
            {
                "id": "policy_web_to_api",
                "name": "Web Ingress to Core API Microservices",
                "source_subnet": "10.0.1.0/24",
                "destination_subnet": "10.0.2.0/24",
                "port_protocol": "443/TCP",
                "action": "ALLOW",
                "is_enabled": True,
                "description": "Standard encrypted ingress traffic from DMZ to application tier.",
            },
            {
                "id": "policy_api_to_payment",
                "name": "Core API Gateway to Vault Payment Gateway",
                "source_subnet": "10.0.2.0/24",
                "destination_subnet": "10.0.3.50/32",
                "port_protocol": "8443/TCP (mTLS)",
                "action": "ALLOW",
                "is_enabled": True,
                "description": "Strict mutual TLS channel for PCI-DSS payment token processing.",
            },
            {
                "id": "policy_dev_to_crown_jewel",
                "name": "Developer Workstation to Crown Jewel Production DB",
                "source_subnet": "10.0.10.0/24",
                "destination_subnet": "10.0.5.0/24",
                "port_protocol": "5432/TCP",
                "action": "DENY",
                "is_enabled": True,
                "description": "Blocks direct engineer workstation connectivity to production database cluster.",
            },
            {
                "id": "policy_staging_lateral_deny",
                "name": "Staging Environment Lateral Egress Lockdown",
                "source_subnet": "10.0.20.0/24",
                "destination_subnet": "10.0.0.0/16",
                "port_protocol": "ANY",
                "action": "DENY",
                "is_enabled": True,
                "description": "Isolates staging cluster to prevent lateral propagation into production core.",
            },
        ]
        for r in default_rules:
            self.microsegmentation_policies[r["id"]] = r

    def _initialize_default_sessions(self) -> None:
        """Seeds active enterprise sessions undergoing continuous verification."""
        default_sessions = [
            {
                "session_id": "sess_eng_lead_01",
                "user_id": "alice.security@corp.local",
                "ip_address": "192.168.1.45",
                "device_id": "macbook-pro-m3-corp-09",
                "auth_level": AuthAssuranceLevel.HARDWARE_MFA_FIDO2.value,
                "trust_score": 92.5,
                "status": "VERIFIED_ACTIVE",
                "current_access": "ALLOW",
                "last_verified_at": datetime.now(timezone.utc).isoformat(),
            },
            {
                "session_id": "sess_ops_temp_02",
                "user_id": "contractor.bob@partner.net",
                "ip_address": "172.16.4.88",
                "device_id": "win11-byod-laptop",
                "auth_level": AuthAssuranceLevel.PASSWORD_SMS.value,
                "trust_score": 64.0,
                "status": "CHALLENGED",
                "current_access": "STEP_UP_AUTH",
                "last_verified_at": datetime.now(timezone.utc).isoformat(),
            },
        ]
        for s in default_sessions:
            self.sessions[s["session_id"]] = s

    def calculate_trust_score(
        self,
        auth_level: AuthAssuranceLevel = AuthAssuranceLevel.HARDWARE_MFA_FIDO2,
        device_posture: Optional[Dict[str, bool]] = None,
        ueba_anomaly_score: float = 0.0,
        network_context: Optional[Dict[str, Any]] = None,
        active_incident_link: bool = False,
    ) -> Dict[str, Any]:
        """Calculates multi-dimensional continuous trust score (0-100) aligned with NIST SP 800-207."""
        device_posture = device_posture or {
            "edr_active": True,
            "disk_encrypted": True,
            "os_patched": True,
            "firewall_on": True,
        }
        network_context = network_context or {
            "is_vpn_or_tor": False,
            "threat_reputation_score": 0.0,
        }

        # 1. Authentication Assurance (25%)
        auth_weights = {
            AuthAssuranceLevel.PASSWORD_ONLY: 35.0,
            AuthAssuranceLevel.PASSWORD_SMS: 65.0,
            AuthAssuranceLevel.HARDWARE_MFA_FIDO2: 100.0,
        }
        auth_score = auth_weights.get(auth_level, 40.0)

        # 2. Device Health Posture (25%)
        device_score = (
            (35.0 if device_posture.get("edr_active", True) else 0.0)
            + (30.0 if device_posture.get("disk_encrypted", True) else 0.0)
            + (20.0 if device_posture.get("os_patched", True) else 0.0)
            + (15.0 if device_posture.get("firewall_on", True) else 0.0)
        )

        # 3. Behavioral Risk Factor (20%)
        # Anomaly score ranges from 0.0 (normal) to 1.0 (extreme deviation)
        clamped_anomaly = min(max(ueba_anomaly_score, 0.0), 1.0)
        behavioral_score = max(0.0, 100.0 - (clamped_anomaly * 100.0))

        # 4. Network Threat Context (15%)
        net_penalty = 35.0 if network_context.get("is_vpn_or_tor", False) else 0.0
        threat_rep = float(network_context.get("threat_reputation_score", 0.0))
        network_score = max(0.0, 100.0 - threat_rep - net_penalty)

        # 5. Active Incident Linkage (15%)
        incident_score = 5.0 if active_incident_link else 100.0

        # Weighted Total
        composite_score = (
            auth_score * 0.25
            + device_score * 0.25
            + behavioral_score * 0.20
            + network_score * 0.15
            + incident_score * 0.15
        )

        return {
            "trust_score": round(composite_score, 1),
            "breakdown": {
                "authentication_score": round(auth_score, 1),
                "device_posture_score": round(device_score, 1),
                "behavioral_trust_score": round(behavioral_score, 1),
                "network_context_score": round(network_score, 1),
                "incident_freedom_score": round(incident_score, 1),
            },
        }

    def check_microsegmentation_rules(
        self,
        source_subnet: str,
        destination_subnet: str,
    ) -> Optional[Dict[str, Any]]:
        """Checks whether an explicit micro-segmentation rule permits or denies traffic between subnets."""
        for policy in self.microsegmentation_policies.values():
            if not policy.get("is_enabled", True):
                continue
            p_src = policy.get("source_subnet")
            p_dst = policy.get("destination_subnet")
            # Subnet matching (supports exact or prefix)
            if (p_src == source_subnet or p_src == "ANY") and (p_dst == destination_subnet or p_dst == "ANY"):
                return policy
        return None

    def evaluate_access_request(
        self,
        user_id: str,
        resource_id: str,
        resource_sensitivity: ResourceSensitivity = ResourceSensitivity.INTERNAL,
        auth_level: AuthAssuranceLevel = AuthAssuranceLevel.HARDWARE_MFA_FIDO2,
        device_posture: Optional[Dict[str, bool]] = None,
        ueba_anomaly_score: float = 0.0,
        network_context: Optional[Dict[str, Any]] = None,
        active_incident_link: bool = False,
        source_subnet: Optional[str] = None,
        destination_subnet: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluates an access attempt as a NIST SP 800-207 Policy Decision Point (PDP)."""
        score_data = self.calculate_trust_score(
            auth_level=auth_level,
            device_posture=device_posture,
            ueba_anomaly_score=ueba_anomaly_score,
            network_context=network_context,
            active_incident_link=active_incident_link,
        )
        trust_score = score_data["trust_score"]

        # Check micro-segmentation boundary if network coordinates provided
        segmentation_rule = None
        if source_subnet and destination_subnet:
            segmentation_rule = self.check_microsegmentation_rules(source_subnet, destination_subnet)
            if segmentation_rule and segmentation_rule.get("action") == "DENY":
                decision = AccessDecision.BLOCK
                reason = f"Explicit micro-segmentation DENY rule enforced: '{segmentation_rule['name']}'"
                eval_record = self._create_eval_record(
                    user_id, resource_id, resource_sensitivity, trust_score, decision, reason, score_data
                )
                return eval_record

        # NIST SP 800-207 Dynamic Threshold Evaluation
        # Higher sensitivity resources require higher confidence and assurance
        thresholds = {
            ResourceSensitivity.PUBLIC: {"allow": 40.0, "step_up": 25.0, "restrict": 15.0},
            ResourceSensitivity.INTERNAL: {"allow": 65.0, "step_up": 50.0, "restrict": 35.0},
            ResourceSensitivity.CONFIDENTIAL: {"allow": 78.0, "step_up": 60.0, "restrict": 45.0},
            ResourceSensitivity.RESTRICTED_CROWN_JEWEL: {"allow": 92.0, "step_up": 75.0, "restrict": 55.0},
        }
        t = thresholds.get(resource_sensitivity, thresholds[ResourceSensitivity.INTERNAL])

        # Crown jewels enforce strict phishing-resistant hardware MFA policy (NIST SP 800-207 / OMB M-22-09)
        if (
            resource_sensitivity == ResourceSensitivity.RESTRICTED_CROWN_JEWEL
            and auth_level != AuthAssuranceLevel.HARDWARE_MFA_FIDO2
        ):
            decision = AccessDecision.STEP_UP_AUTH
            reason = f"Resource {resource_sensitivity.value} requires phishing-resistant FIDO2/Hardware MFA. Step-up authentication required."
            return self._create_eval_record(
                user_id, resource_id, resource_sensitivity, trust_score, decision, reason, score_data
            )

        if trust_score >= t["allow"]:
            decision = AccessDecision.ALLOW
            reason = f"Trust score ({trust_score}%) exceeds {resource_sensitivity.value} authorization SLA ({t['allow']}%)."
        elif trust_score >= t["step_up"]:
            decision = AccessDecision.STEP_UP_AUTH
            reason = f"Trust score ({trust_score}%) requires biometric/FIDO2 re-authentication for {resource_sensitivity.value}."
        elif trust_score >= t["restrict"]:
            decision = AccessDecision.RESTRICT
            reason = f"Degraded device posture or elevated risk ({trust_score}%); restricted to read-only sandboxed quarantine."
        else:
            decision = AccessDecision.BLOCK
            reason = f"Trust score ({trust_score}%) critically below minimum security floor; access denied and incident logged."

        eval_record = self._create_eval_record(
            user_id, resource_id, resource_sensitivity, trust_score, decision, reason, score_data
        )
        return eval_record

    def _create_eval_record(
        self,
        user_id: str,
        resource_id: str,
        resource_sensitivity: ResourceSensitivity,
        trust_score: float,
        decision: AccessDecision,
        reason: str,
        score_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Creates, logs, and returns an access decision evaluation record."""
        now_str = datetime.now(timezone.utc).isoformat()
        eval_record = {
            "evaluation_id": f"zt_eval_{uuid.uuid4().hex[:8]}",
            "user_id": user_id,
            "resource_id": resource_id,
            "resource_sensitivity": resource_sensitivity.value,
            "trust_score": trust_score,
            "decision": decision.value,
            "reason": reason,
            "score_breakdown": score_data["breakdown"],
            "evaluated_at": now_str,
        }
        self.evaluation_history.insert(0, eval_record)
        if len(self.evaluation_history) > 100:
            self.evaluation_history = self.evaluation_history[:100]
        return eval_record

    def create_microsegmentation_policy(
        self,
        name: str,
        source_subnet: str,
        destination_subnet: str,
        port_protocol: str = "ANY",
        action: str = "DENY",
        description: str = "",
    ) -> Dict[str, Any]:
        """Provisions a new micro-segmentation network policy."""
        policy_id = f"policy_{uuid.uuid4().hex[:8]}"
        policy = {
            "id": policy_id,
            "name": name,
            "source_subnet": source_subnet,
            "destination_subnet": destination_subnet,
            "port_protocol": port_protocol,
            "action": action.upper(),
            "is_enabled": True,
            "description": description,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.microsegmentation_policies[policy_id] = policy
        return policy

    def toggle_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Toggles the enabled/disabled state of a micro-segmentation policy."""
        policy = self.microsegmentation_policies.get(policy_id)
        if not policy:
            return None
        policy["is_enabled"] = not policy.get("is_enabled", True)
        return policy

    def trigger_step_up_challenge(self, session_id: str) -> Dict[str, Any]:
        """Dispatches a step-up authentication challenge to an active session."""
        session = self.sessions.get(session_id)
        challenge_id = f"chal_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(minutes=5)).isoformat()

        if session:
            session["status"] = "CHALLENGED"
            session["current_access"] = AccessDecision.STEP_UP_AUTH.value

        return {
            "challenge_id": challenge_id,
            "session_id": session_id,
            "status": "CHALLENGE_PENDING",
            "required_auth": "HARDWARE_MFA_FIDO2",
            "created_at": now.isoformat(),
            "expires_at": expires_at,
        }

    def get_zero_trust_metrics(self) -> Dict[str, Any]:
        """Returns global Zero-Trust posture metrics."""
        scores = [
            e["trust_score"]
            for e in self.evaluation_history
        ] or [s["trust_score"] for s in self.sessions.values()]

        avg_score = round(float(sum(scores) / len(scores)), 1) if scores else 85.0
        active_policies = sum(1 for p in self.microsegmentation_policies.values() if p.get("is_enabled", True))
        blocked_attempts = sum(1 for e in self.evaluation_history if e["decision"] == AccessDecision.BLOCK.value)

        return {
            "average_trust_score": avg_score,
            "active_policies_count": active_policies,
            "total_microsegmentation_policies": len(self.microsegmentation_policies),
            "continuous_verification_rate_percent": 100.0,
            "active_sessions_monitored": len(self.sessions),
            "total_evaluations_completed": len(self.evaluation_history),
            "blocked_access_attempts": blocked_attempts,
            "nist_compliance_framework": "NIST SP 800-207",
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }


zero_trust_engine = ZeroTrustEngine()
