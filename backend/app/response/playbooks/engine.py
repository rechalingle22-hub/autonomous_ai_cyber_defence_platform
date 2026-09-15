# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""SOAR Playbook Execution Engine with Failure Compensation and HITL Gating."""

import os
import sys
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.config.settings import settings
from backend.app.models.response import ActionType, ActionStatus, ResponseAction
from backend.app.response.models import (
    PlaybookDefinition,
    PlaybookStep,
    ActionResult,
    PlaybookExecutionResult,
)
from backend.app.response.actions import ACTION_REGISTRY

logger = logging.getLogger("cyberdefense.soar.engine")


class PlaybookEngine:
    """Executes multi-step containment workflows with safety verification and rollback support."""

    async def execute_playbook(
        self,
        playbook: PlaybookDefinition,
        incident_context: Dict[str, Any],
        is_simulation: Optional[bool] = None,
        auto_approve_all: bool = False,
        db_session: Optional[AsyncSession] = None,
    ) -> PlaybookExecutionResult:
        """Executes playbook steps sequentially against incident context."""
        started_at = datetime.now(timezone.utc)
        sim_mode = is_simulation if is_simulation is not None else getattr(settings, "SIMULATION_MODE", True)
        incident_id = str(incident_context.get("incident_id") or incident_context.get("id") or "INC-STANDALONE")

        step_results: List[ActionResult] = []
        executed_steps: List[tuple[PlaybookStep, str]] = []
        pending_approvals = 0
        execution_failed = False

        for step in playbook.steps:
            # 1. Resolve target entity
            target = incident_context.get(step.target_field)
            if not target:
                # Fallbacks
                if "ip" in step.target_field.lower():
                    target = incident_context.get("source_ip") or incident_context.get("destination_ip") or "198.51.100.2"
                elif "user" in step.target_field.lower():
                    target = incident_context.get("user_id") or incident_context.get("affected_user") or "admin"
                else:
                    target = incident_context.get("primary_host") or incident_context.get("hostname") or "sec-srv-01"

            target_entity = str(target)

            # 2. Evaluate Human-in-the-Loop (HITL) requirements
            hitl_enforced = getattr(settings, "REQUIRE_HUMAN_APPROVAL_FOR_CONTAINMENT", True)
            requires_approval = not auto_approve_all and (
                step.requires_approval or (hitl_enforced and step.risk_impact_score >= 50.0)
            )

            if requires_approval:
                pending_approvals += 1
                result = ActionResult(
                    action_type=step.action_type,
                    target_entity=target_entity,
                    is_simulation=sim_mode,
                    status=ActionStatus.PENDING_APPROVAL,
                    success=True,
                    detail=(
                        f"Action '{step.name}' on {target_entity} requires analyst authorization "
                        f"(Risk Score: {step.risk_impact_score})."
                    ),
                    metadata={"step_id": step.step_id, "requires_approval": True},
                )
                step_results.append(result)

                # Persist pending record in database
                if db_session:
                    try:
                        ra = ResponseAction(
                            incident_id=incident_id,
                            action_type=step.action_type,
                            target_entity=target_entity,
                            is_simulation=sim_mode,
                            status=ActionStatus.PENDING_APPROVAL,
                            rationale=f"Playbook {playbook.playbook_id}: {step.name}",
                            risk_impact_score=step.risk_impact_score,
                        )
                        db_session.add(ra)
                        await db_session.commit()
                    except Exception as e:
                        logger.warning("Could not persist pending ResponseAction: %s", str(e))
                continue

            # 3. Execute Action Handler
            handler = ACTION_REGISTRY.get(step.action_type)
            if not handler:
                logger.error("No registered action handler for action type: %s", step.action_type)
                continue

            try:
                result = await handler.execute(
                    target_entity=target_entity,
                    context=incident_context,
                    is_simulation=sim_mode,
                )
                step_results.append(result)

                if result.success:
                    executed_steps.append((step, target_entity))
                    if db_session:
                        try:
                            ra = ResponseAction(
                                incident_id=incident_id,
                                action_type=step.action_type,
                                target_entity=target_entity,
                                is_simulation=sim_mode,
                                status=ActionStatus.EXECUTED,
                                rationale=f"Playbook {playbook.playbook_id}: {step.name}",
                                risk_impact_score=step.risk_impact_score,
                                executed_at=datetime.now(timezone.utc),
                            )
                            db_session.add(ra)
                            await db_session.commit()
                        except Exception as e:
                            logger.warning("Could not persist executed ResponseAction: %s", str(e))
                else:
                    execution_failed = True
                    # Compensatory rollback on failure
                    if step.rollback_on_failure:
                        logger.warning("Step '%s' failed. Initiating automated compensatory rollback...", step.name)
                        await self._compensate(executed_steps, incident_context, sim_mode)
                    break

            except Exception as e:
                logger.error("Execution error in playbook step '%s': %s", step.name, str(e), exc_info=True)
                execution_failed = True
                if step.rollback_on_failure:
                    await self._compensate(executed_steps, incident_context, sim_mode)
                break

        completed_at = datetime.now(timezone.utc)
        successful_steps = len([r for r in step_results if r.status == ActionStatus.EXECUTED and r.success])
        failed_steps = len([r for r in step_results if not r.success])

        return PlaybookExecutionResult(
            playbook_id=playbook.playbook_id,
            incident_id=incident_id,
            success=not execution_failed,
            steps_executed=successful_steps,
            steps_failed=failed_steps,
            step_results=step_results,
            pending_approvals_count=pending_approvals,
            started_at=started_at,
            completed_at=completed_at,
        )

    async def _compensate(
        self,
        executed_steps: List[tuple[PlaybookStep, str]],
        context: Dict[str, Any],
        is_simulation: bool,
    ) -> None:
        """Rolls back executed actions in reverse chronological order."""
        for step, target in reversed(executed_steps):
            handler = ACTION_REGISTRY.get(step.action_type)
            if handler:
                try:
                    await handler.rollback(target, context=context, is_simulation=is_simulation)
                    logger.info("Rollback compensated for step '%s' on '%s'.", step.name, target)
                except Exception as re:
                    logger.error("Error compensating step '%s': %s", step.name, str(re))


playbook_engine = PlaybookEngine()

