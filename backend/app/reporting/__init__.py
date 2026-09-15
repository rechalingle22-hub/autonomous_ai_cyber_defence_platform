# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Security Reporting Package Initialization."""


import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from .engine import SecurityReportEngine, report_engine  # type: ignore
from .builders.executive import ExecutiveReportBuilder  # type: ignore
from .builders.technical import TechnicalDossierBuilder  # type: ignore
from .builders.compliance import ComplianceReportBuilder  # type: ignore
from .renderers.html_renderer import HTMLReportRenderer  # type: ignore
from .renderers.markdown_renderer import MarkdownReportRenderer  # type: ignore
from .renderers.json_renderer import JSONReportRenderer  # type: ignore
from .renderers.csv_renderer import CSVReportRenderer  # type: ignore

__all__ = [
    "SecurityReportEngine",
    "report_engine",
    "ExecutiveReportBuilder",
    "TechnicalDossierBuilder",
    "ComplianceReportBuilder",
    "HTMLReportRenderer",
    "MarkdownReportRenderer",
    "JSONReportRenderer",
    "CSVReportRenderer",
]
