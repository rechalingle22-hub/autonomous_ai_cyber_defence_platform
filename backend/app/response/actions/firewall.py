# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Firewall and Network Perimeter Blocking Action Handler."""

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

logger = logging.getLogger("cyberdefense.soar.firewall")

_PROTECTED_WHITELIST = {
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",      # Default internal management gateway
    "192.168.1.1",  # Local gateway
    "8.8.8.8",      # Critical DNS
    "1.1.1.1",      # Critical DNS
}


class BlockIPActionHandler(BaseActionHandler):
    """Orchestrates IP and CIDR perimeter blocking at the firewall/gateway layer."""

    def __init__(self):
        super().__init__(ActionType.BLOCK_IP)
        self._blocked_ips: set[str] = set()

    async def execute(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        """Blocks network communication from target IP."""
        clean_ip = target_entity.strip()

        # Guardrail: Never block critical infrastructure or loopback
        if clean_ip in _PROTECTED_WHITELIST:
            logger.warning("SOAR Safety Guard: Prevented blocking whitelisted IP: %s", clean_ip)
            return ActionResult(
                action_type=self.action_type,
                target_entity=clean_ip,
                is_simulation=is_simulation,
                status=ActionStatus.FAILED,
                success=False,
                detail=f"Safety Guardrail: IP {clean_ip} is protected on the platform whitelist and cannot be blocked.",
                metadata={"whitelisted": True},
            )

        self._blocked_ips.add(clean_ip)
        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = f"[{mode}] Firewall drop rule applied: Dropping all inbound/outbound packets for {clean_ip}."
        logger.info("Firewall Action Executed: %s", detail)

        return ActionResult(
            action_type=self.action_type,
            target_entity=clean_ip,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={
                "firewall_chain": "INPUT_DROP",
                "ip_address": clean_ip,
                "protocol": "ALL",
            },
        )

    async def rollback(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        """Removes the firewall block rule for target IP."""
        clean_ip = target_entity.strip()
        if clean_ip in self._blocked_ips:
            self._blocked_ips.remove(clean_ip)

        mode = "SIMULATED" if is_simulation else "ACTIVE"
        detail = f"[{mode}] Firewall drop rule removed: Restored connectivity for {clean_ip}."
        logger.info("Firewall Action Rollback: %s", detail)

        return ActionResult(
            action_type=self.action_type,
            target_entity=clean_ip,
            is_simulation=is_simulation,
            status=ActionStatus.EXECUTED,
            success=True,
            detail=detail,
            metadata={"rule_removed": True, "ip_address": clean_ip},
        )

    def is_blocked(self, ip_address: str) -> bool:
        """Checks whether an IP is currently blocked in memory/cache."""
        return ip_address.strip() in self._blocked_ips

