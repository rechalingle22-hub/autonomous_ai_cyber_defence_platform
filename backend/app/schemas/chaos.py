# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic schemas and DTOs for Security Chaos Engineering and Adversarial Resilience."""

import os
import sys
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict  # type: ignore

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


class ChaosInjectRequest(BaseModel):
    experiment_type: str = Field(
        description="Type of fault: BROKER_LATENCY, BROKER_DROP, DB_PARTITION, AGENT_TIMEOUT, TELEMETRY_BURST"
    )
    duration_seconds: int = Field(default=30, ge=5, le=120)
    params: Dict[str, Any] = Field(default_factory=dict)


class ChaosExperimentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    experiment_type: str
    status: str
    duration_seconds: int
    started_at: str
    expires_at: str
    params: Dict[str, Any]
    metrics: Dict[str, Any]


class ChaosStatusResponse(BaseModel):
    resilience_score: float
    system_state: str
    active_faults_count: int
    mean_time_to_recovery_ms: float
    zero_downtime_guaranteed: bool
    in_memory_fallbacks_operational: bool
    active_experiments: List[ChaosExperimentResponse]
    last_evaluated_at: str


class AdversarialEvaluateRequest(BaseModel):
    perturbation_epsilon: float = Field(default=0.15, ge=0.01, le=0.50)
    technique: str = Field(default="BENIGN_MIMICRY", description="BENIGN_MIMICRY, GAUSSIAN_PERTURBATION, or HYBRID")


class AdversarialEvaluateResponse(BaseModel):
    total_attack_samples_tested: int
    perturbation_epsilon: float
    technique_applied: str
    ensemble_adversarial_robustness_index: float
    ensemble_robustness_grade: str
    models: Dict[str, Any]

