# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""ML Monitoring & Drift Detection Package Initialization."""

from .drift_detector import DataDriftDetector, drift_detector

__all__ = ["DataDriftDetector", "drift_detector"]
