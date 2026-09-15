# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Detection API router for real-time anomaly inference and model management."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path:
        sys.path.insert(0, p)

from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from backend.app.detection.inference_engine import inference_engine
from backend.app.schemas.common_event import CommonEventSchema

router = APIRouter(prefix="/detection", tags=["AI/ML Detection Engine"])


class BatchAnalysisRequest(BaseModel):
    events: List[CommonEventSchema]


@router.get("/status")
async def get_detection_status() -> Dict[str, Any]:
    """Returns the operational status of all loaded anomaly detectors, classifiers, and XAI explainer."""
    return {
        "is_ready": inference_engine.is_ready,
        "models_loaded": {
            "preprocessor": inference_engine.preprocessor is not None,
            "isolation_forest": inference_engine.isolation_forest is not None,
            "autoencoder": inference_engine.autoencoder is not None,
            "random_forest": inference_engine.random_forest is not None,
            "xgboost": inference_engine.xgboost is not None,
            "shap_explainer": inference_engine.explainer is not None,
        },
        "classes": (
            inference_engine.xgboost.classes_
            if inference_engine.xgboost
            else []
        ),
        "thresholds": {
            "autoencoder_reconstruction_threshold": (
                inference_engine.autoencoder.threshold
                if inference_engine.autoencoder
                else None
            ),
            "isolation_forest_contamination": (
                inference_engine.isolation_forest.contamination
                if inference_engine.isolation_forest
                else None
            ),
        },
    }


@router.post("/analyze")
async def analyze_telemetry_event(event: CommonEventSchema) -> Dict[str, Any]:
    """Evaluates a normalized telemetry event using the full hybrid detection & classification ensemble."""
    try:
        result = inference_engine.analyze_event(event.model_dump())
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference execution failed: {str(e)}",
        )


@router.post("/classify")
async def classify_telemetry_event(event: CommonEventSchema) -> Dict[str, Any]:
    """Dedicated endpoint returning attack classification and SHAP local feature attribution."""
    try:
        result = inference_engine.analyze_event(event.model_dump())
        return {
            "event_id": result["event_id"],
            "prediction": result["prediction"],
            "attack_type": result["attack_type"],
            "confidence": result["confidence"],
            "severity": result["severity"],
            "xai_explanation": result.get("xai_explanation", {}),
            "latency_ms": result["latency_ms"],
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Classification execution failed: {str(e)}",
        )


@router.post("/analyze-batch")
async def analyze_telemetry_batch(req: BatchAnalysisRequest) -> List[Dict[str, Any]]:
    """Evaluates a batch of telemetry events in a single high-throughput inference pass."""
    try:
        events_dicts = [ev.model_dump() for ev in req.events]
        results = inference_engine.analyze_batch(events_dicts)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch inference failed: {str(e)}",
        )


@router.post("/train-unsupervised")
async def trigger_unsupervised_training() -> Dict[str, Any]:
    """Triggers retraining of Isolation Forest and Deep Autoencoder on baseline telemetry."""
    from ml.training.train_unsupervised import train_and_evaluate
    try:
        artifacts = train_and_evaluate()
        inference_engine._load_models()
        return {
            "status": "TRAINING_SUCCESSFUL",
            "artifacts": artifacts,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unsupervised training failed: {str(e)}",
        )


@router.post("/train-supervised")
async def trigger_supervised_training() -> Dict[str, Any]:
    """Triggers retraining of Random Forest, XGBoost, and LSTM on synthetic & benchmark attacks."""
    from ml.training.train_supervised import train_and_evaluate_supervised
    try:
        metrics = train_and_evaluate_supervised()
        inference_engine._load_models()
        return {
            "status": "TRAINING_SUCCESSFUL",
            "metrics": metrics,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Supervised training failed: {str(e)}",
        )

