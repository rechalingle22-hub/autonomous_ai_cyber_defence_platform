"""Detection package initialization."""

from backend.app.detection.inference_engine import (
    HybridDetectionInferenceEngine,
    UnsupervisedInferenceEngine,
    inference_engine,
)

__all__ = ["HybridDetectionInferenceEngine", "UnsupervisedInferenceEngine", "inference_engine"]

