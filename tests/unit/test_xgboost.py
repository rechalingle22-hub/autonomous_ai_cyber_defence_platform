"""Unit tests for XGBoost Attack Classifier."""

import os
import tempfile
import numpy as np
import pytest
from ml.models.xgboost.model import XGBoostAttackClassifier


def test_xgboost_fit_and_predict():
    """Tests training and multiclass inference with XGBoost."""
    np.random.seed(42)
    n_samples = 150
    n_features = 14
    X = np.random.randn(n_samples, n_features)

    classes = ["BENIGN", "PORT_SCAN", "DATA_EXFILTRATION"]
    y = np.random.choice(classes, size=n_samples)

    xgb = XGBoostAttackClassifier(n_estimators=15, max_depth=4, random_state=42)
    xgb.fit(X, y)

    assert xgb.is_trained
    assert set(xgb.classes_) == set(classes)

    preds = xgb.predict(X[:5])
    assert len(preds) == 5
    assert all(p in classes for p in preds)

    probs = xgb.predict_proba(X[:5])
    assert probs.shape == (5, 3)
    np.testing.assert_allclose(probs.sum(axis=1), np.ones(5), atol=1e-4)

    score = xgb.score_single(X[0])
    assert "attack_type" in score
    assert "confidence" in score
    assert 0.0 <= score["confidence"] <= 1.0


def test_xgboost_serialization():
    """Tests saving and reloading XGBoost model artifact."""
    np.random.seed(42)
    X = np.random.randn(60, 14)
    y = np.array(["BENIGN"] * 30 + ["PORT_SCAN"] * 30)

    xgb = XGBoostAttackClassifier(n_estimators=10, random_state=42)
    xgb.fit(X, y)

    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        xgb.save(tmp_path)
        assert os.path.exists(tmp_path)

        loaded_xgb = XGBoostAttackClassifier.load(tmp_path)
        assert loaded_xgb.is_trained
        assert loaded_xgb.classes_ == xgb.classes_

        orig_preds = xgb.predict(X[:5])
        loaded_preds = loaded_xgb.predict(X[:5])
        assert list(orig_preds) == list(loaded_preds)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

