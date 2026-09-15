# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Pydantic schemas and DTOs for MLOps and Model Governance."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict  # type: ignore


class FeatureDriftDetail(BaseModel):
    feature: str
    psi: float
    ks_statistic: float
    ks_pvalue: float
    baseline_mean: float
    current_mean: float
    baseline_std: float
    current_std: float
    drift_detected: bool
    status: str


class DriftEvaluationResponse(BaseModel):
    drift_detected: bool
    status: str
    mean_psi: float
    max_psi: float
    drifted_features_count: int
    total_features_evaluated: int
    drifted_features: List[str]
    feature_metrics: Dict[str, FeatureDriftDetail]
    evaluated_at: str


class DriftEvaluateRequest(BaseModel):
    sample_count: int = Field(default=200, ge=50, le=1000)
    introduce_drift: bool = Field(default=False, description="Simulates severe concept and covariate drift")


class ModelVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    model_id: str
    version: str
    validation_f1: float
    validation_precision: float
    validation_recall: float
    artifact_path: str
    is_deployed: bool
    trained_at: datetime


class MLModelResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    model_name: str
    model_family: str
    active_version: Optional[str]
    created_at: datetime
    versions: List[ModelVersionResponse] = []


class RetrainRequest(BaseModel):
    trigger_reason: str = Field(default="MANUAL", description="Reason for initiating model retraining")
    auto_promote: bool = Field(default=True, description="Whether to automatically promote if validation gate passes")


class RetrainResponse(BaseModel):
    job_id: str
    version: str
    trigger_reason: str
    training_samples: int
    validation_samples: int
    models_evaluated: Dict[str, Any]
    status: str
    completed_at: str
