"""Unit tests for TreeSHAP ModelExplainer."""

import numpy as np
import pytest
from ml.models.xgboost.model import XGBoostAttackClassifier
from ml.explainability.shap_explainer import ModelExplainer
from ml.features.definitions import NUMERICAL_FEATURES


def test_shap_explainer_with_xgboost():
    """Tests TreeSHAP feature attribution ranking on XGBoost."""
    np.random.seed(42)
    n_samples = 100
    n_features = len(NUMERICAL_FEATURES)
    X = np.random.randn(n_samples, n_features)

    # Synthetic labels
    classes = ["BENIGN", "DOS_DDOS"]
    y = np.array(["BENIGN"] * 50 + ["DOS_DDOS"] * 50)

    # Ensure DOS_DDOS has distinct high values in total_fwd_bytes (feature index 3)
    X[50:, 3] += 5.0

    xgb = XGBoostAttackClassifier(n_estimators=10, max_depth=3, random_state=42)
    xgb.fit(X, y)

    explainer = ModelExplainer(xgb, feature_names=NUMERICAL_FEATURES)

    # Explain a DOS_DDOS sample
    test_sample = X[75]
    explanation = explainer.explain_prediction(
        test_sample,
        predicted_class_idx=1,
        raw_feature_values={feat: float(test_sample[i]) for i, feat in enumerate(NUMERICAL_FEATURES)},
        top_k=3,
    )

    assert explanation["explanation_method"] == "TreeSHAP"
    assert "predicted_category" in explanation
    assert "deterministic_summary" in explanation
    assert len(explanation["contributing_factors"]) == 3

    factors = explanation["contributing_factors"]
    assert factors[0]["rank"] == 1
    assert "shap_attribution" in factors[0]
    assert "impact" in factors[0]
    assert factors[0]["impact"] in ["INCREASED_RISK", "DECREASED_RISK"]
    assert "description" in factors[0]

