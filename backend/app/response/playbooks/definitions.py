# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Declarative SOAR Playbook Definitions."""

import os
import sys
from typing import List, Dict, Optional, Any

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.response import ActionType
from backend.app.response.models import PlaybookDefinition, PlaybookStep


_DEFAULT_PLAYBOOKS = [
    # 1. Ransomware Containment Playbook
    PlaybookDefinition(
        playbook_id="PB-RANSOMWARE-01",
        name="Ransomware Rapid Containment",
        description="Quarantines host, severs C2 communication, revokes user credentials, and triggers forensic baseline snapshot.",
        trigger_criteria={"attack_stage": "IMPACT", "attack_category": "RANSOMWARE"},
        steps=[
            PlaybookStep(
                step_id="step_1_isolate",
                name="Quarantine Infected Host",
                action_type=ActionType.ISOLATE_HOST,
                target_field="primary_host",
                risk_impact_score=80.0,
                requires_approval=True,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step_2_block_c2",
                name="Block Outbound C2 Destination IP",
                action_type=ActionType.BLOCK_IP,
                target_field="destination_ip",
                risk_impact_score=40.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step_3_revoke_user",
                name="Invalidate User Session & Lock Credentials",
                action_type=ActionType.REVOKE_SESSION,
                target_field="affected_user",
                risk_impact_score=50.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step_4_monitor",
                name="Elevate Subnet Monitoring to 100%",
                action_type=ActionType.INCREASE_MONITORING,
                target_field="primary_host",
                risk_impact_score=10.0,
                requires_approval=False,
                rollback_on_failure=False,
            ),
            PlaybookStep(
                step_id="step_5_recovery",
                name="Verify Forensic Snapshot & Recovery Baseline",
                action_type=ActionType.SIMULATE_RECOVERY,
                target_field="primary_host",
                risk_impact_score=10.0,
                requires_approval=False,
                rollback_on_failure=False,
            ),
        ],
    ),
    # 2. Data Exfiltration Playbook
    PlaybookDefinition(
        playbook_id="PB-EXFILTRATION-01",
        name="Data Exfiltration Neutralization",
        description="Blocks exfiltration destination IP, throttles suspect host bandwidth, and enables deep packet inspection.",
        trigger_criteria={"attack_stage": "EXFILTRATION", "attack_category": "EXFILTRATION"},
        steps=[
            PlaybookStep(
                step_id="step_1_block_dest",
                name="Block Exfiltration Destination IP",
                action_type=ActionType.BLOCK_IP,
                target_field="destination_ip",
                risk_impact_score=40.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step_2_throttle",
                name="Throttle Source Host Egress Bandwidth",
                action_type=ActionType.THROTTLE_BANDWIDTH,
                target_field="source_ip",
                risk_impact_score=45.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step_3_monitor",
                name="Increase Host Monitoring",
                action_type=ActionType.INCREASE_MONITORING,
                target_field="source_ip",
                risk_impact_score=10.0,
                requires_approval=False,
                rollback_on_failure=False,
            ),
        ],
    ),
    # 3. Credential Access & Brute Force Playbook
    PlaybookDefinition(
        playbook_id="PB-CREDENTIAL-01",
        name="Credential Compromise Mitigation",
        description="Blocks external brute-force attacker IP, terminates compromised sessions, and forces password rotation.",
        trigger_criteria={"attack_stage": "INITIAL_ACCESS", "attack_category": "BRUTE_FORCE"},
        steps=[
            PlaybookStep(
                step_id="step_1_block_attacker",
                name="Block Attacker Origin IP",
                action_type=ActionType.BLOCK_IP,
                target_field="source_ip",
                risk_impact_score=35.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step_2_revoke_session",
                name="Revoke Compromised User Session",
                action_type=ActionType.REVOKE_SESSION,
                target_field="affected_user",
                risk_impact_score=40.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step_3_monitor",
                name="Monitor Authentication Telemetry",
                action_type=ActionType.INCREASE_MONITORING,
                target_field="affected_user",
                risk_impact_score=10.0,
                requires_approval=False,
                rollback_on_failure=False,
            ),
        ],
    ),
    # 4. Port Scan Reconnaissance Playbook
    PlaybookDefinition(
        playbook_id="PB-RECON-01",
        name="Port Scan & Reconnaissance Suppression",
        description="Automatically drops scanning source IP at perimeter firewall.",
        trigger_criteria={"attack_stage": "RECONNAISSANCE", "attack_category": "PORT_SCAN"},
        steps=[
            PlaybookStep(
                step_id="step_1_block_scanner",
                name="Block Scanner Source IP",
                action_type=ActionType.BLOCK_IP,
                target_field="source_ip",
                risk_impact_score=20.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step_2_monitor",
                name="Monitor Target Asset",
                action_type=ActionType.INCREASE_MONITORING,
                target_field="destination_ip",
                risk_impact_score=10.0,
                requires_approval=False,
                rollback_on_failure=False,
            ),
        ],
    ),
]


class PlaybookRegistry:
    """Stores and retrieves registered SOAR Playbook specifications."""

    def __init__(self):
        self._playbooks_by_id: Dict[str, PlaybookDefinition] = {}
        for pb in _DEFAULT_PLAYBOOKS:
            self.register(pb)

    def register(self, playbook: PlaybookDefinition) -> None:
        """Adds a playbook definition to the registry."""
        self._playbooks_by_id[playbook.playbook_id] = playbook

    def get(self, playbook_id: str) -> Optional[PlaybookDefinition]:
        """Looks up a playbook definition by ID."""
        return self._playbooks_by_id.get(playbook_id)

    def list_all(self) -> List[PlaybookDefinition]:
        """Returns all registered playbooks."""
        return list(self._playbooks_by_id.values())

    def match_playbook(self, attack_stage: Optional[str] = None, attack_category: Optional[str] = None) -> Optional[PlaybookDefinition]:
        """Finds most appropriate playbook matching an incident's classification and stage."""
        stage_upper = (attack_stage or "").upper()
        cat_upper = (attack_category or "").upper()

        if "RANSOMWARE" in cat_upper or "IMPACT" in stage_upper:
            return self.get("PB-RANSOMWARE-01")
        if "EXFILTRATION" in cat_upper or "EXFILTRATION" in stage_upper:
            return self.get("PB-EXFILTRATION-01")
        if "BRUTE_FORCE" in cat_upper or "CREDENTIAL" in cat_upper or "INITIAL_ACCESS" in stage_upper:
            return self.get("PB-CREDENTIAL-01")
        if "PORT_SCAN" in cat_upper or "RECON" in stage_upper:
            return self.get("PB-RECON-01")

        # Default fallback to Recon
        return self.get("PB-RECON-01")


playbook_registry = PlaybookRegistry()
