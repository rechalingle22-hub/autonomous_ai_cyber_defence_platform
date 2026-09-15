"""XGBoost Multi-Class Attack Classifier for Security Telemetry."""

import os
import joblib
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import xgboost as xgb
from ml.features.definitions import ATTACK_CATEGORIES


from sklearn.preprocessing import LabelEncoder


class XGBoostAttackClassifier:
    """Gradient boosted decision tree classifier for high-precision cyber threat classification."""

    def __init__(
        self,
        n_estimators: int = 150,
        max_depth: int = 6,
        learning_rate: float = 0.08,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.random_state = random_state
        self.classes_: List[str] = list(ATTACK_CATEGORIES)
        self.label_encoder: Optional[LabelEncoder] = None
        self.model: Optional[xgb.XGBClassifier] = None
        self.is_fitted: bool = False

    @property
    def is_trained(self) -> bool:
        return self.is_fitted

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        eval_set: Optional[List[Tuple[np.ndarray, np.ndarray]]] = None,
        classes: Optional[List[str]] = None,
    ) -> "XGBoostAttackClassifier":
        """Fits XGBoost classifier on training split with optional early stopping validation."""
        if classes:
            self.classes_ = list(classes)

        # Check if y_train is strings/objects
        is_string_labels = (
            len(y_train) > 0
            and (isinstance(y_train[0], (str, np.str_)) or getattr(y_train, "dtype", None) is not None and y_train.dtype.kind in ("U", "S", "O"))
        )

        if is_string_labels:
            self.label_encoder = LabelEncoder()
            y_encoded = self.label_encoder.fit_transform(y_train)
            self.classes_ = [str(c) for c in self.label_encoder.classes_]
            num_classes = len(self.classes_)
            if eval_set:
                eval_set = [(ex, self.label_encoder.transform(ey)) for ex, ey in eval_set]
        else:
            y_encoded = np.asarray(y_train, dtype=int)
            num_classes = len(self.classes_) if self.classes_ else len(np.unique(y_encoded))

        self.model = xgb.XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            objective="multi:softprob",
            num_class=max(2, num_classes),
            eval_metric="mlogloss",
            random_state=self.random_state,
            n_jobs=-1,
        )

        self.model.fit(
            X_train,
            y_encoded,
            eval_set=eval_set,
            verbose=False,
        )
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predicts class labels for input feature matrix."""
        if not self.is_fitted or self.model is None:
            raise RuntimeError("XGBoost model must be fitted before predict()")

        probs = self.model.predict_proba(X)
        pred_indices = np.argmax(probs, axis=1)

        if self.label_encoder is not None:
            return self.label_encoder.inverse_transform(pred_indices)
        if self.classes_ and len(self.classes_) > int(np.max(pred_indices)):
            return np.array([self.classes_[int(idx)] for idx in pred_indices])
        return pred_indices

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predicts class probabilities for input feature matrix."""
        if not self.is_fitted or self.model is None:
            raise RuntimeError("XGBoost model must be fitted before predict_proba()")
        return self.model.predict_proba(X)

    def score_single(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Classifies a single telemetry event feature vector."""
        X = feature_vector.reshape(1, -1) if feature_vector.ndim == 1 else feature_vector
        probs = self.predict_proba(X)
        pred_idx = int(np.argmax(probs[0]))
        conf = float(probs[0][pred_idx])

        if self.label_encoder is not None:
            class_name = str(self.label_encoder.inverse_transform([pred_idx])[0])
        elif self.classes_ and pred_idx < len(self.classes_):
            class_name = str(self.classes_[pred_idx])
        else:
            class_name = "ANOMALOUS_OTHER"

        return {
            "attack_type": class_name,
            "confidence": float(np.round(conf, 4)),
            "model": "XGBOOST",
            "class_probabilities": {
                str(self.classes_[i]) if i < len(self.classes_) else f"class_{i}": float(np.round(probs[0][i], 4))
                for i in range(min(len(self.classes_), probs.shape[1]))
            },
        }

    def save(self, filepath: str) -> None:
        """Serializes model to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "classes_": self.classes_,
                "label_encoder": self.label_encoder,
                "is_fitted": self.is_fitted,
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth,
                "learning_rate": self.learning_rate,
            },
            filepath,
        )

    @classmethod
    def load(cls, filepath: str) -> "XGBoostAttackClassifier":
        """Loads serialized model from disk."""
        data = joblib.load(filepath)
        classifier = cls(
            n_estimators=data["n_estimators"],
            max_depth=data["max_depth"],
            learning_rate=data["learning_rate"],
        )
        classifier.model = data["model"]
        classifier.classes_ = data["classes_"]
        classifier.label_encoder = data.get("label_encoder")
        classifier.is_fitted = data["is_fitted"]
        return classifier

