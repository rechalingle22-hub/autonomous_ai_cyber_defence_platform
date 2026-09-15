# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Alert correlation and incident synthesis package."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

try:
    from .rules import CorrelationRules, STAGE_WEIGHTS, ATTACK_TYPE_MAPPING  # type: ignore
    from .incident_builder import IncidentBuilder  # type: ignore
    from .engine import AlertCorrelationEngine, correlation_engine  # type: ignore
except (ImportError, ValueError):
    from backend.app.correlation.rules import CorrelationRules, STAGE_WEIGHTS, ATTACK_TYPE_MAPPING  # type: ignore
    from backend.app.correlation.incident_builder import IncidentBuilder  # type: ignore
    from backend.app.correlation.engine import AlertCorrelationEngine, correlation_engine  # type: ignore

__all__ = [
    "CorrelationRules",
    "STAGE_WEIGHTS",
    "ATTACK_TYPE_MAPPING",
    "IncidentBuilder",
    "AlertCorrelationEngine",
    "correlation_engine",
]
