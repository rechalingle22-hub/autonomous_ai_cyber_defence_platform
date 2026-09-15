# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit test suite for Phase 9 Automated Incident Response & SOAR Engine."""

import os
import sys
import uuid
import pytest
from datetime import datetime, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.response import ActionType, ActionStatus
from backend.app.response.models import (
    ActionResult,
    PlaybookDefinition,
    PlaybookStep,
    PlaybookExecutionResult,
)
from backend.app.response.actions.firewall import BlockIPActionHandler
from backend.app.response.actions.host_isolation import IsolateHostActionHandler
from backend.app.response.actions.identity import (
    RevokeSessionActionHandler,
    ThrottleBandwidthActionHandler,
    IncreaseMonitoringActionHandler,
)
from backend.app.response.actions import ACTION_REGISTRY
from backend.app.response.playbooks.definitions import PlaybookRegistry
from backend.app.response.playbooks.engine import PlaybookEngine
from backend.app.response.dispatcher import ResponseDispatcher


@pytest.mark.asyncio
async def test_block_ip_action_simulation():
    """Verifies IP blocking in simulation mode."""
    handler = BlockIPActionHandler()
    target_ip = "198.51.100.42"

    result = await handler.execute(
        target_entity=target_ip,
        context={"direction": "both", "duration_seconds": 3600},
        is_simulation=True,
    )
    assert result.success is True
    assert result.status == ActionStatus.EXECUTED
    assert result.is_simulation is True
    assert target_ip in result.detail
    assert handler.is_blocked(target_ip) is True


@pytest.mark.asyncio
async def test_block_ip_rollback():
    """Verifies unblocking rollback for previously blocked IP."""
    handler = BlockIPActionHandler()
    target_ip = "198.51.100.43"

    await handler.execute(target_ip, is_simulation=True)
    assert handler.is_blocked(target_ip) is True

    res = await handler.rollback(target_ip, is_simulation=True)
    assert res.success is True
    assert res.status == ActionStatus.EXECUTED
    assert "restored" in res.detail.lower()
    assert handler.is_blocked(target_ip) is False


@pytest.mark.asyncio
async def test_block_ip_protected_whitelist_guardrail():
    """Ensures safety whitelist prevents blocking loopback, gateways, or public DNS."""
    handler = BlockIPActionHandler()
    protected_ips = ["127.0.0.1", "::1", "localhost", "10.0.0.1", "192.168.1.1", "8.8.8.8", "1.1.1.1"]

    for ip in protected_ips:
        res = await handler.execute(target_entity=ip, is_simulation=True)
        assert res.success is False
        assert res.status == ActionStatus.FAILED
        assert "whitelist" in res.detail.lower() or "protected" in res.detail.lower()
        assert handler.is_blocked(ip) is False


@pytest.mark.asyncio
async def test_isolate_host_and_rollback():
    """Verifies network isolation of compromised host and subsequent restoration."""
    handler = IsolateHostActionHandler()
    target_host = "srv-finance-01.corp"

    exec_res = await handler.execute(
        target_entity=target_host,
        context={"allow_soc_management": True},
        is_simulation=True,
    )
    assert exec_res.success is True
    assert exec_res.status == ActionStatus.EXECUTED
    assert "quarantined" in exec_res.detail.lower() or "isolated" in exec_res.detail.lower()
    assert handler.is_isolated(target_host) is True

    # Test reconnection rollback
    rb_res = await handler.rollback(
        target_entity=target_host,
        context=exec_res.metadata,
        is_simulation=True,
    )
    assert rb_res.success is True
    assert rb_res.status == ActionStatus.EXECUTED
    assert "reconnected" in rb_res.detail.lower()
    assert handler.is_isolated(target_host) is False


@pytest.mark.asyncio
async def test_revoke_session_and_rollback():
    """Verifies user credential session revocation and simulated session reactivation."""
    handler = RevokeSessionActionHandler()
    user = "analyst_bob"

    res = await handler.execute(
        target_entity=user,
        context={"reason": "Compromised credentials detected via impossible travel"},
        is_simulation=True,
    )
    assert res.success is True
    assert res.status == ActionStatus.EXECUTED
    assert user in res.detail

    # Rollback
    rb_res = await handler.rollback(
        target_entity=user,
        is_simulation=True,
    )
    assert rb_res.success is True
    assert rb_res.status == ActionStatus.EXECUTED


@pytest.mark.asyncio
async def test_throttle_bandwidth_and_monitoring():
    """Verifies rate limiting and monitoring elevation actions."""
    throttle_handler = ThrottleBandwidthActionHandler()
    target = "10.200.5.15"

    th_res = await throttle_handler.execute(
        target_entity=target,
        context={"rate_limit": "256kbps"},
        is_simulation=True,
    )
    assert th_res.success is True
    assert th_res.status == ActionStatus.EXECUTED

    rb_th = await throttle_handler.rollback(target, is_simulation=True)
    assert rb_th.success is True
    assert rb_th.status == ActionStatus.EXECUTED

    monitor_handler = IncreaseMonitoringActionHandler()
    db_target = "srv-db-primary"
    mon_res = await monitor_handler.execute(
        target_entity=db_target,
        context={"log_level": "DEBUG", "sample_rate": 1.0},
        is_simulation=True,
    )
    assert mon_res.success is True
    assert mon_res.status == ActionStatus.EXECUTED


def test_action_registry_completeness():
    """Ensures all enum ActionTypes have a registered handler."""
    for action_type in ActionType:
        assert action_type in ACTION_REGISTRY, f"ActionType.{action_type.name} missing from ACTION_REGISTRY"


def test_playbook_registry_default_playbooks():
    """Validates pre-packaged playbooks in PlaybookRegistry."""
    registry = PlaybookRegistry()
    playbooks = registry.list_all()
    assert len(playbooks) >= 4

    p_ids = {p.playbook_id for p in playbooks}
    assert "PB-RANSOMWARE-01" in p_ids
    assert "PB-EXFILTRATION-01" in p_ids
    assert "PB-CREDENTIAL-01" in p_ids
    assert "PB-RECON-01" in p_ids

    # Query matching
    matched_rw = registry.match_playbook(attack_category="ransomware")
    assert matched_rw is not None
    assert matched_rw.playbook_id == "PB-RANSOMWARE-01"

    matched_exfil = registry.match_playbook(attack_stage="EXFILTRATION")
    assert matched_exfil is not None
    assert matched_exfil.playbook_id == "PB-EXFILTRATION-01"


@pytest.mark.asyncio
async def test_playbook_engine_execution_simulation():
    """Tests complete automated playbook run without approvals required."""
    engine = PlaybookEngine()

    test_playbook = PlaybookDefinition(
        playbook_id="PB-TEST-AUTO-01",
        name="Automated Test Playbook",
        description="Automated playbook for testing",
        steps=[
            PlaybookStep(
                step_id="step-1",
                name="Increase Monitoring",
                action_type=ActionType.INCREASE_MONITORING,
                target_field="target_host",
                risk_impact_score=10.0,
                requires_approval=False,
            ),
            PlaybookStep(
                step_id="step-2",
                name="Block Source IP",
                action_type=ActionType.BLOCK_IP,
                target_field="source_ip",
                risk_impact_score=20.0,
                requires_approval=False,
            ),
        ],
    )

    incident_ctx = {
        "id": "inc-" + str(uuid.uuid4())[:8],
        "target_host": "srv-app-02",
        "source_ip": "203.0.113.88",
    }

    result = await engine.execute_playbook(test_playbook, incident_ctx, is_simulation=True)
    assert result.success is True
    assert len(result.step_results) == 2
    assert result.step_results[0].status == ActionStatus.EXECUTED
    assert result.step_results[1].status == ActionStatus.EXECUTED
    assert result.pending_approvals_count == 0


@pytest.mark.asyncio
async def test_playbook_engine_hitl_approval_gating():
    """Tests playbook halts execution on steps configured with requires_approval=True."""
    engine = PlaybookEngine()

    test_playbook = PlaybookDefinition(
        playbook_id="PB-TEST-HITL-01",
        name="HITL Test Playbook",
        description="HITL gating test",
        steps=[
            PlaybookStep(
                step_id="step-1",
                name="Increase Monitoring",
                action_type=ActionType.INCREASE_MONITORING,
                target_field="target_host",
                risk_impact_score=10.0,
                requires_approval=False,
            ),
            PlaybookStep(
                step_id="step-2",
                name="Isolate Production DB",
                action_type=ActionType.ISOLATE_HOST,
                target_field="target_host",
                risk_impact_score=85.0,
                requires_approval=True,  # Explicitly requires approval
            ),
        ],
    )

    incident_ctx = {
        "id": "inc-" + str(uuid.uuid4())[:8],
        "target_host": "srv-prod-db",
    }

    result = await engine.execute_playbook(test_playbook, incident_ctx, is_simulation=True)
    assert result.success is True
    assert len(result.step_results) == 2
    assert result.step_results[0].status == ActionStatus.EXECUTED
    assert result.step_results[1].status == ActionStatus.PENDING_APPROVAL
    assert result.pending_approvals_count == 1


@pytest.mark.asyncio
async def test_playbook_engine_compensatory_rollback():
    """Tests that when a step fails, prior steps are compensated via rollback."""
    engine = PlaybookEngine()
    target_ip = "198.51.100.88"

    # Step 1: Blocks an IP
    # Step 2: Attempts to block 127.0.0.1 (protected whitelist, guaranteed to fail)
    test_playbook = PlaybookDefinition(
        playbook_id="PB-TEST-FAIL-COMPENSATE",
        name="Compensatory Rollback Test Playbook",
        description="Testing automated rollback upon failure",
        steps=[
            PlaybookStep(
                step_id="step-1-block",
                name="Block External Attacker",
                action_type=ActionType.BLOCK_IP,
                target_field="external_ip",
                risk_impact_score=25.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
            PlaybookStep(
                step_id="step-2-illegal-block",
                name="Block Protected Gateway (Will Fail)",
                action_type=ActionType.BLOCK_IP,
                target_field="protected_ip",
                risk_impact_score=25.0,
                requires_approval=False,
                rollback_on_failure=True,
            ),
        ],
    )

    incident_ctx = {
        "id": "inc-rollback-test",
        "external_ip": target_ip,
        "protected_ip": "127.0.0.1",  # triggers failure
    }

    result = await engine.execute_playbook(test_playbook, incident_ctx, is_simulation=True)
    assert result.success is False
    assert result.steps_failed >= 1

    # Check that Step 1 was rolled back
    fw_handler: BlockIPActionHandler = ACTION_REGISTRY[ActionType.BLOCK_IP]
    assert fw_handler.is_blocked(target_ip) is False


@pytest.mark.asyncio
async def test_response_dispatcher_incident_dispatch():
    """Validates dispatcher matching and triggering for incoming incident payload."""
    dispatcher = ResponseDispatcher()

    incident_payload = {
        "id": "inc-simulated-exfil-99",
        "attack_stage": "EXFILTRATION",
        "attack_category": "Data Exfiltration",
        "source_ip": "198.51.100.77",
        "destination_ip": "203.0.113.5",
        "target_host": "workstation-hr-05",
        "risk_score": 45.0,
    }

    result = await dispatcher.handle_incident(incident_payload, is_simulation=True)
    assert result is not None
    assert result.playbook_id == "PB-EXFILTRATION-01"
    assert len(result.step_results) >= 2

