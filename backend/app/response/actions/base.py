# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Abstract Base Class for Automated SOAR Response Actions."""

import os
import sys
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.models.response import ActionType, ActionStatus
from backend.app.response.models import ActionResult


class BaseActionHandler(ABC):
    """Abstract interface defining execution and compensatory rollback for an action."""

    def __init__(self, action_type: ActionType):
        self.action_type = action_type

    @abstractmethod
    async def execute(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        """Executes containment action (or dry-run simulation)."""
        pass

    @abstractmethod
    async def rollback(
        self,
        target_entity: str,
        context: Optional[Dict[str, Any]] = None,
        is_simulation: bool = True,
    ) -> ActionResult:
        """Performs idempotent compensatory rollback undoing the action."""
        pass

