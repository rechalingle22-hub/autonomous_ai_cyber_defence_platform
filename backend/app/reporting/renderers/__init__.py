# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""Reporting renderers package initialization."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from .html_renderer import HTMLReportRenderer  # type: ignore
from .markdown_renderer import MarkdownReportRenderer  # type: ignore
from .json_renderer import JSONReportRenderer  # type: ignore
from .csv_renderer import CSVReportRenderer  # type: ignore

__all__ = [
    "HTMLReportRenderer",
    "MarkdownReportRenderer",
    "JSONReportRenderer",
    "CSVReportRenderer",
]
