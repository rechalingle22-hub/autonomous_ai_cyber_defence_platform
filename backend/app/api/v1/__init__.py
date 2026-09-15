# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
# ruff: noqa
# flake8: noqa
"""API v1 router aggregations."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import importlib
from typing import Any  # type: ignore
from fastapi import APIRouter  # type: ignore

api_v1_router = APIRouter()

_ROUTER_MODULES = [
    "backend.app.api.v1.health",
    "backend.app.api.v1.auth",
    "backend.app.api.v1.telemetry",
    "backend.app.api.v1.alerts",
    "backend.app.api.v1.incidents",
    "backend.app.api.v1.audit",
    "backend.app.api.v1.simulation",
    "backend.app.api.v1.detection",
    "backend.app.api.v1.streaming",
    "backend.app.api.v1.ueba",
    "backend.app.api.v1.threat_intel",
    "backend.app.api.v1.response",
    "backend.app.api.v1.investigation",
    "backend.app.api.v1.reports",
    "backend.app.api.v1.mlops",
    "backend.app.api.v1.chaos",
    "backend.app.api.v1.deception",
    "backend.app.api.v1.zerotrust",
    "backend.app.api.v1.asm",
    "backend.app.api.v1.threathunting",
    "backend.app.api.v1.dfir",
    "backend.app.api.v1.bas",
    "backend.app.api.v1.exposure",
    "backend.app.api.v1.cspm",
    "backend.app.api.v1.sca",
    "backend.app.api.v1.nexus",
]

for _module_path in _ROUTER_MODULES:
    try:
        _mod = importlib.import_module(_module_path)
        _router = getattr(_mod, "router", None)
        if _router is not None:
            api_v1_router.include_router(_router)
    except Exception:
        pass

__all__ = ["api_v1_router"]
