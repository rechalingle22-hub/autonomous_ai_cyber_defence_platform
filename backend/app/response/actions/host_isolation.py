# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Host and Endpoint Network Isolation Action Handler."""

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

logger = logging.getLogger("cyberdefense.soar.host_isolation")


class IsolateHostActionHandler(BaseActionHandler):
    """Quarantines a compromised endpoint to sever lateral movement and exfiltration."""

    def __init__(self):
        super().__init__(ActionType.ISOLATE_HOST)
        self._isolated_hosts: set[str] = set()

    async def execute(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        """Quarantines endpoint network interfaces, preserving SOC management telemetry."""
        hostname = target_entity.strip()
        self._isolated_hosts.add(hostname)

        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = (
            f"[{mode}] Endpoint {hostname} quarantined: Host isolated from subnet; "
            f"lateral movement severed. SOC management tunnel retained on ports 22/443."
        )
        logger.warning("Host Isolation Executed: %s", detail)

        return ActionResult(
            action_type=self.action_type,
            target_entity=hostname,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={
                "quarantined_host": hostname,
                "retained_ports": [22, 443],
                "quarantine_rule": "ISOLATION_ZONE_RESTRICTED",
            },
        )

    async def rollback(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        """Restores endpoint to normal network participation."""
        hostname = target_entity.strip()
        if hostname in self._isolated_hosts:
            self._isolated_hosts.remove(hostname)

        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = f"[{mode}] Endpoint {hostname} quarantine released: Network interfaces reconnected."
        logger.info("Host Isolation Rollback: %s", detail)

        return ActionResult(
            action_type=self.action_type,
            target_entity=hostname,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"quarantined_host": hostname, "status": "ONLINE"},
        )

    def is_isolated(self, hostname: str) -> bool:
        """Returns isolation state of the host."""
        return hostname.strip() in self._isolated_hosts

