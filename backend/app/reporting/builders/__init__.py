# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Reporting builders package initialization."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from .executive import ExecutiveReportBuilder  # type: ignore
from .technical import TechnicalDossierBuilder  # type: ignore
from .compliance import ComplianceReportBuilder  # type: ignore

__all__ = [
    "ExecutiveReportBuilder",
    "TechnicalDossierBuilder",
    "ComplianceReportBuilder",
]
