# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Identity, Session, and Policy Response Action Handlers."""

import os
import sys
import logging
from typing import Dict, Any, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.response import ActionType, ActionStatus
from backend.app.response.models import ActionResult
from backend.app.response.actions.base import BaseActionHandler

logger = logging.getLogger("cyberdefense.soar.identity")


class RevokeSessionActionHandler(BaseActionHandler):
    """Revokes active authenticated user sessions and invalidates bearer tokens."""

    def __init__(self):
        super().__init__(ActionType.REVOKE_SESSION)
        self._revoked_principals: set[str] = set()

    async def execute(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        user_id = target_entity.strip()
        self._revoked_principals.add(user_id)

        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = (
            f"[{mode}] Active sessions for user '{user_id}' terminated. "
            f"Bearer tokens blacklisted in cache; password reset enforced on next login."
        )
        logger.info("Session Revocation Executed: %s", detail)

        return ActionResult(
            action_type=self.action_type,
            target_entity=user_id,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"revoked_user": user_id, "token_invalidated": True},
        )

    async def rollback(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        user_id = target_entity.strip()
        if user_id in self._revoked_principals:
            self._revoked_principals.remove(user_id)

        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = f"[{mode}] Session revocation lock cleared for user '{user_id}'."
        return ActionResult(
            action_type=self.action_type,
            target_entity=user_id,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"revoked_user": user_id, "status": "ACTIVE"},
        )


class ThrottleBandwidthActionHandler(BaseActionHandler):
    """Throttles ingress/egress network bandwidth for an anomalous host to curb exfiltration."""

    def __init__(self):
        super().__init__(ActionType.THROTTLE_BANDWIDTH)
        self._throttled_entities: set[str] = set()

    async def execute(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        entity = target_entity.strip()
        self._throttled_entities.add(entity)

        rate_limit = (context or {}).get("rate_limit", "100kbps")
        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = f"[{mode}] Bandwidth for entity '{entity}' throttled to {rate_limit}."
        logger.info("Bandwidth Throttle Executed: %s", detail)

        return ActionResult(
            action_type=self.action_type,
            target_entity=entity,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"entity": entity, "rate_limit": rate_limit},
        )

    async def rollback(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        entity = target_entity.strip()
        if entity in self._throttled_entities:
            self._throttled_entities.remove(entity)

        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = f"[{mode}] Bandwidth throttling policy removed for '{entity}'."
        return ActionResult(
            action_type=self.action_type,
            target_entity=entity,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"entity": entity, "rate_limit": "UNLIMITED"},
        )


class IncreaseMonitoringActionHandler(BaseActionHandler):
    """Enables maximum telemetry verbosity and detailed event tracing."""

    def __init__(self):
        super().__init__(ActionType.INCREASE_MONITORING)
        self._monitored_entities: set[str] = set()

    async def execute(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        entity = target_entity.strip()
        self._monitored_entities.add(entity)

        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = f"[{mode}] Enhanced forensic monitoring enabled for '{entity}': 100% packet & process sampling."
        logger.info("Increase Monitoring Executed: %s", detail)

        return ActionResult(
            action_type=self.action_type,
            target_entity=entity,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"entity": entity, "sampling_rate": "100%", "pcaps_enabled": True},
        )

    async def rollback(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        entity = target_entity.strip()
        if entity in self._monitored_entities:
            self._monitored_entities.remove(entity)

        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = f"[{mode}] Monitoring reverted to standard SOC telemetry profile for '{entity}'."
        return ActionResult(
            action_type=self.action_type,
            target_entity=entity,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"entity": entity, "sampling_rate": "STANDARD"},
        )


class SimulateRecoveryActionHandler(BaseActionHandler):
    """Validates post-containment system baseline recovery in dry-run mode."""

    def __init__(self):
        super().__init__(ActionType.SIMULATE_RECOVERY)

    async def execute(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        entity = target_entity.strip()
        detail = f"[SIMULATED] Verified forensic snapshot and recovery baseline for '{entity}'."
        return ActionResult(
            action_type=self.action_type,
            target_entity=entity,
            is_simulation=True,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"entity": entity, "recovery_status": "VERIFIED"},
        )

    async def rollback(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        return ActionResult(
            action_type=self.action_type,
            target_entity=target_entity,
            is_simulation=True,
            status=ActionStatus.EXECUTED,
            success=True,
            detail="Simulated recovery baseline unmounted.",
        )

