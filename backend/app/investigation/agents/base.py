# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Base Abstract Class for Specialized AI SOC Investigation Agents."""

import os
import sys
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.investigation.models import AgentScratchpadEntry

logger = logging.getLogger("cyberdefense.investigation.agent")


class BaseSOCAgent(ABC):
    """Abstract interface defining standard reasoning and evidence gathering workflows."""

    def __init__(self, role_name: str, tier: int):
        self.role_name = role_name
        self.tier = tier
        self.scratchpad: List[AgentScratchpadEntry] = []

    def record_step(self, thought: str, action: str, observations: str) -> AgentScratchpadEntry:
        """Records an introspective reasoning step into the agent's audit scratchpad."""
        entry = AgentScratchpadEntry(
            agent_role=self.role_name,
            thought_process=thought,
            action_taken=action,
            observations=observations,
            timestamp=datetime.now(timezone.utc),
        )
        self.scratchpad.append(entry)
        logger.debug("[%s] %s -> %s", self.role_name, action, observations)
        return entry

    @abstractmethod
    async def analyze(
        self,
        incident_context: Dict[str, Any],
        working_memory: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Performs specialized analysis, returning structured findings."""
        pass

    def get_scratchpad_history(self) -> List[Dict[str, Any]]:
        """Returns JSON-serializable list of scratchpad entries."""
        return [entry.model_dump(mode="json") for entry in self.scratchpad]

    def clear_scratchpad(self) -> None:
        """Resets the scratchpad for a new investigation round."""
        self.scratchpad = []

