# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Incident Response Dispatcher and Human-in-the-Loop Approval Manager."""

import os
import sys
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.response import ActionType, ActionStatus, ResponseAction, ResponseApproval
from backend.app.response.models import (
    ActionResult,
    PlaybookExecutionResult,
)
from backend.app.response.actions import ACTION_REGISTRY
from backend.app.response.playbooks import playbook_registry, playbook_engine
from backend.app.api.websockets.manager import ws_manager
from backend.app.audit.service import audit_service

logger = logging.getLogger("cyberdefense.soar.dispatcher")


class ResponseDispatcher:
    """Manages manual and automated incident response actions, approvals, and playbooks."""

    async def handle_incident(
        self,
        incident_dict: Dict[str, Any],
        is_simulation: bool = True,
        db_session: Optional[AsyncSession] = None,
    ) -> Optional[PlaybookExecutionResult]:
        """Automatically evaluates an incident and dispatches matching containment playbooks."""
        attack_stage = incident_dict.get("attack_stage")
        attack_cat = incident_dict.get("attack_category") or incident_dict.get("title")

        playbook = playbook_registry.match_playbook(attack_stage=attack_stage, attack_category=attack_cat)
        if not playbook:
            logger.info("No matching response playbook for incident: %s", incident_dict.get("id"))
            return None

        logger.info("Executing Playbook '%s' for Incident '%s'", playbook.name, incident_dict.get("id"))
        result = await playbook_engine.execute_playbook(
            playbook=playbook,
            incident_context=incident_dict,
            is_simulation=is_simulation,
            db_session=db_session,
        )

        # Broadcast SOAR event to SOC analysts
        await ws_manager.broadcast({
            "type": "SOAR_PLAYBOOK_EXECUTED",
            "playbook_id": playbook.playbook_id,
            "incident_id": incident_dict.get("id"),
            "success": result.success,
            "pending_approvals": result.pending_approvals_count,
        })

        return result

    async def approve_action(
        self,
        action_id: str,
        analyst_id: str,
        comments: Optional[str] = None,
        db_session: Optional[AsyncSession] = None,
    ) -> ActionResult:
        """Processes analyst approval and triggers actual containment execution."""
        action = None
        if db_session:
            stmt = select(ResponseAction).where(ResponseAction.id == action_id)
            res = await db_session.execute(stmt)
            action = res.scalar_one_or_none()

        if not action:
            return ActionResult(
                action_type=ActionType.BLOCK_IP,
                target_entity="UNKNOWN",
                is_simulation=True,
                status=ActionStatus.FAILED,
                success=False,
                detail=f"Response action {action_id} not found",
            )

        handler = ACTION_REGISTRY.get(action.action_type)
        if not handler:
            return ActionResult(
                action_type=action.action_type,
                target_entity=action.target_entity,
                is_simulation=action.is_simulation,
                status=ActionStatus.FAILED,
                success=False,
                detail=f"Handler for {action.action_type} not found",
            )

        # Execute containment
        result = await handler.execute(
            target_entity=action.target_entity,
            is_simulation=action.is_simulation,
        )

        if db_session:
            action.status = ActionStatus.EXECUTED if result.success else ActionStatus.FAILED
            action.executed_at = datetime.now(timezone.utc)

            approval = ResponseApproval(
                response_action_id=action.id,
                approved_by_id=analyst_id,
                decision="APPROVED",
                comments=comments or "Analyst approved containment action",
            )
            db_session.add(approval)
            await db_session.commit()

            # Record audit log
            await audit_service.log_event(
                db=db_session,
                action="SOAR_ACTION_APPROVED",
                resource_type="RESPONSE_ACTION",
                resource_id=action.id,
                user_id=analyst_id,
                details={
                    "action_type": action.action_type.value,
                    "target": action.target_entity,
                    "comments": comments,
                },
            )

        # Broadcast update
        await ws_manager.broadcast({
            "type": "SOAR_ACTION_STATUS_CHANGED",
            "action_id": action_id,
            "new_status": ActionStatus.EXECUTED.value,
        })

        return result

    async def reject_action(
        self,
        action_id: str,
        analyst_id: str,
        comments: Optional[str] = None,
        db_session: Optional[AsyncSession] = None,
    ) -> bool:
        """Processes analyst rejection of automated containment proposal."""
        if db_session:
            stmt = select(ResponseAction).where(ResponseAction.id == action_id)
            res = await db_session.execute(stmt)
            action = res.scalar_one_or_none()

            if action:
                action.status = ActionStatus.REJECTED
                approval = ResponseApproval(
                    response_action_id=action.id,
                    approved_by_id=analyst_id,
                    decision="REJECTED",
                    comments=comments or "Analyst rejected automated containment",
                )
                db_session.add(approval)
                await db_session.commit()

                await audit_service.log_event(
                    db=db_session,
                    action="SOAR_ACTION_REJECTED",
                    resource_type="RESPONSE_ACTION",
                    resource_id=action.id,
                    user_id=analyst_id,
                    details={"action_type": action.action_type.value, "comments": comments},
                )

                await ws_manager.broadcast({
                    "type": "SOAR_ACTION_STATUS_CHANGED",
                    "action_id": action_id,
                    "new_status": ActionStatus.REJECTED.value,
                })
                return True
        return False

    async def rollback_action(
        self,
        action_id: str,
        analyst_id: str,
        db_session: Optional[AsyncSession] = None,
    ) -> ActionResult:
        """Executes compensatory rollback on an executed action."""
        action = None
        if db_session:
            stmt = select(ResponseAction).where(ResponseAction.id == action_id)
            res = await db_session.execute(stmt)
            action = res.scalar_one_or_none()

        if not action:
            return ActionResult(
                action_type=ActionType.BLOCK_IP,
                target_entity="UNKNOWN",
                is_simulation=True,
                status=ActionStatus.FAILED,
                success=False,
                detail=f"Action {action_id} not found",
            )

        handler = ACTION_REGISTRY.get(action.action_type)
        if not handler:
            return ActionResult(
                action_type=action.action_type,
                target_entity=action.target_entity,
                is_simulation=action.is_simulation,
                status=ActionStatus.FAILED,
                success=False,
                detail="Handler not found",
            )

        result = await handler.rollback(
            target_entity=action.target_entity,
            is_simulation=action.is_simulation,
        )

        if db_session and result.success:
            # Mark action as rejected or neutralized
            action.status = ActionStatus.REJECTED
            await db_session.commit()

            await audit_service.log_event(
                db=db_session,
                action="SOAR_ACTION_ROLLED_BACK",
                resource_type="RESPONSE_ACTION",
                resource_id=action.id,
                user_id=analyst_id,
                details={"action_type": action.action_type.value, "target": action.target_entity},
            )

        return result


response_dispatcher = ResponseDispatcher()

