# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Base class definition for Threat Intelligence feed providers."""

import os
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.threat_intel.models import IOCRecord


class BaseFeedProvider(ABC):
    """Abstract base class for all CTI feed collectors and adapters."""

    def __init__(self, name: str, source_id: str, poll_interval_seconds: int = 3600):
        self.name = name
        self.source_id = source_id
        self.poll_interval = poll_interval_seconds
        self.last_fetched: Optional[datetime] = None
        self.total_indicators_collected = 0

    @abstractmethod
    async def fetch_indicators(self) -> List[IOCRecord]:
        """Asynchronously collects, normalizes, and returns IOC records from the feed."""
        pass

