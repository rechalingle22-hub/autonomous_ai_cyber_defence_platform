"""Isolation Forest Unsupervised Anomaly Detector for Cybersecurity Telemetry.

Identifies novel intrusions and unusual telemetry outliers without requiring prior attack labels.
"""

import os
import joblib
from typing import Dict, Any, Tuple, Optional
import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestAnomalyDetector:
    """Unsupervised anomaly detector based on isolation trees."""

    def __init__(
        self,
        n_estimators: int = 150,
        contamination: float = 0.03,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.is_fitted: bool = False
        self.score_min: float = -0.5
        self.score_max: float = 0.5

    def fit(self, X: np.ndarray) -> "IsolationForestAnomalyDetector":
        """Fits the Isolation Forest on baseline/unlabeled feature matrix."""
        self.model.fit(X)
        self.is_fitted = True

        # Calibrate score scaling based on training decile spread
        raw_scores = self.model.decision_function(X)
        self.score_min = float(np.min(raw_scores))
        self.score_max = float(np.max(raw_scores))
        return self

    def predict_anomaly(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Predicts anomaly status, normalized anomaly score (0-1), and confidence.

        Returns:
            is_anomaly: boolean array (True if anomalous outlier)
            anomaly_score: float array (0.0=normal, 1.0=severely anomalous)
            confidence: float array (0.0 to 1.0 confidence in classification)
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict_anomaly()")

        raw_preds = self.model.predict(X)  # -1 for anomaly, 1 for inlier
        is_anomaly = (raw_preds == -1)

        raw_decision = self.model.decision_function(X)  # Negative indicates anomaly

        # Normalize score into [0.0, 1.0] where 1.0 is highest anomaly
        # Invert so higher value = higher anomaly
        score_range = max(1e-5, (self.score_max - self.score_min))
        normalized_scores = 1.0 - np.clip((raw_decision - self.score_min) / score_range, 0.0, 1.0)

        # Confidence is proportional to distance from the decision boundary (0.0)
        confidence = np.clip(np.abs(raw_decision) * 2.5 + 0.5, 0.5, 0.99)

        return is_anomaly, normalized_scores, confidence

    def score_single(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Convenience method for scoring a single 1D feature array."""
        X = feature_vector.reshape(1, -1) if feature_vector.ndim == 1 else feature_vector
        is_anom, scores, conf = self.predict_anomaly(X)
        return {
            "is_anomaly": bool(is_anom[0]),
            "anomaly_score": float(np.round(scores[0], 4)),
            "confidence": float(np.round(conf[0], 4)),
            "model": "ISOLATION_FOREST",
        }

    def save(self, filepath: str) -> None:
        """Saves fitted model to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "is_fitted": self.is_fitted,
                "score_min": self.score_min,
                "score_max": self.score_max,
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
            },
            filepath,
        )

    @classmethod
    def load(cls, filepath: str) -> "IsolationForestAnomalyDetector":
        """Loads fitted model from disk."""
        data = joblib.load(filepath)
        detector = cls(
            n_estimators=data["n_estimators"],
            contamination=data["contamination"],
        )
        detector.model = data["model"]
        detector.is_fitted = data["is_fitted"]
        detector.score_min = data["score_min"]
        detector.score_max = data["score_max"]
        return detector

