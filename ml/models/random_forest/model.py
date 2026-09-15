"""Random Forest Multi-Class Attack Classifier for Security Telemetry."""

import os
import joblib
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from ml.features.definitions import ATTACK_CATEGORIES


class RandomForestAttackClassifier:
    """Multi-class attack classifier using balanced Random Forest ensemble."""

    def __init__(
        self,
        n_estimators: int = 150,
        max_depth: int = 15,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.classes_ = list(ATTACK_CATEGORIES)
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            class_weight="balanced",
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.is_fitted: bool = False

    @property
    def is_trained(self) -> bool:
        return self.is_fitted

    def fit(self, X: np.ndarray, y: np.ndarray, classes: Optional[List[str]] = None) -> "RandomForestAttackClassifier":
        """Fits the Random Forest classifier on labeled training features."""
        self.model.fit(X, y)
        if classes:
            self.classes_ = list(classes)
        elif hasattr(self.model, "classes_"):
            self.classes_ = [str(c) for c in self.model.classes_]
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predicts class labels for input feature matrix."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict()")

        raw_preds = self.model.predict(X)
        if isinstance(raw_preds[0], (str, np.str_)):
            return raw_preds
        # Map integer indices to class strings if classes_ available
        if self.classes_ and len(self.classes_) > int(np.max(raw_preds)):
            return np.array([self.classes_[int(idx)] for idx in raw_preds])
        return raw_preds

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predicts class probabilities for input feature matrix."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict_proba()")
        return self.model.predict_proba(X)

    def score_single(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Inference for a single feature vector."""
        X = feature_vector.reshape(1, -1) if feature_vector.ndim == 1 else feature_vector
        probs = self.predict_proba(X)
        pred_idx = int(np.argmax(probs[0]))
        conf = float(probs[0][pred_idx])

        if hasattr(self.model, "classes_") and isinstance(self.model.classes_[0], (str, np.str_)):
            class_name = str(self.model.classes_[pred_idx])
        elif self.classes_ and pred_idx < len(self.classes_):
            class_name = str(self.classes_[pred_idx])
        else:
            class_name = "ANOMALOUS_OTHER"

        return {
            "attack_type": class_name,
            "confidence": float(np.round(conf, 4)),
            "model": "RANDOM_FOREST",
        }

    def save(self, filepath: str) -> None:
        """Serializes model to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "classes_": self.classes_,
                "is_fitted": self.is_fitted,
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth,
            },
            filepath,
        )

    @classmethod
    def load(cls, filepath: str) -> "RandomForestAttackClassifier":
        """Loads serialized model from disk."""
        data = joblib.load(filepath)
        classifier = cls(
            n_estimators=data["n_estimators"],
            max_depth=data["max_depth"],
        )
        classifier.model = data["model"]
        classifier.classes_ = data["classes_"]
        classifier.is_fitted = data["is_fitted"]
        return classifier

