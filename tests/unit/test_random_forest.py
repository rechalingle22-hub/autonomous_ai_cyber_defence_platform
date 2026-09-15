"""Unit tests for Random Forest Attack Classifier."""

import os
import tempfile
import numpy as np
import pytest
from ml.models.random_forest.model import RandomForestAttackClassifier


def test_random_forest_fit_and_predict():
    """Tests training and multiclass prediction with Random Forest."""
    np.random.seed(42)
    n_samples = 120
    n_features = 14
    X = np.random.randn(n_samples, n_features)

    # 3 classes: BENIGN, BRUTE_FORCE, DOS_DDOS
    classes = ["BENIGN", "BRUTE_FORCE", "DOS_DDOS"]
    y = np.random.choice(classes, size=n_samples)

    rf = RandomForestAttackClassifier(n_estimators=20, max_depth=5, random_state=42)
    rf.fit(X, y)

    assert rf.is_trained
    assert set(rf.classes_) == set(classes)

    # Predict on test sample
    preds = rf.predict(X[:5])
    assert len(preds) == 5
    assert all(p in classes for p in preds)

    # Predict probabilities
    probs = rf.predict_proba(X[:5])
    assert probs.shape == (5, 3)
    np.testing.assert_allclose(probs.sum(axis=1), np.ones(5), atol=1e-5)

    # Single event scoring
    score = rf.score_single(X[0])
    assert "attack_type" in score
    assert "confidence" in score
    assert 0.0 <= score["confidence"] <= 1.0


def test_random_forest_serialization():
    """Tests saving and loading Random Forest model artifact."""
    np.random.seed(42)
    X = np.random.randn(60, 14)
    y = np.array(["BENIGN"] * 30 + ["DOS_DDOS"] * 30)

    rf = RandomForestAttackClassifier(n_estimators=10, random_state=42)
    rf.fit(X, y)

    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        rf.save(tmp_path)
        assert os.path.exists(tmp_path)

        loaded_rf = RandomForestAttackClassifier.load(tmp_path)
        assert loaded_rf.is_trained
        assert loaded_rf.classes_ == rf.classes_

        orig_preds = rf.predict(X[:5])
        loaded_preds = loaded_rf.predict(X[:5])
        assert list(orig_preds) == list(loaded_preds)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

