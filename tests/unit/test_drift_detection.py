# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Statistical Drift Detection Engine (PSI & KS-test)."""

import os
import sys
import numpy as np
import pandas as pd
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from ml.monitoring.drift_detector import DataDriftDetector, drift_detector
from ml.features.definitions import NUMERICAL_FEATURES


def test_psi_identical_distributions():
    """Identical or near-identical distributions should have near-zero PSI (< 0.05)."""
    np.random.seed(42)
    expected = np.random.normal(50, 10, 1000)
    actual = np.random.normal(50, 10, 1000)

    psi = drift_detector.calculate_psi(expected, actual)
    assert psi < 0.05
    assert psi >= 0.0


def test_psi_significant_drift():
    """Significantly shifted distribution should produce PSI >= 0.25 (CRITICAL)."""
    np.random.seed(42)
    expected = np.random.normal(50, 5, 1000)
    actual = np.random.normal(85, 12, 1000)

    psi = drift_detector.calculate_psi(expected, actual)
    assert psi >= 0.25


def test_ks_test_divergence():
    """KS test on distinct distributions should yield tiny p-value."""
    np.random.seed(42)
    ref = np.random.exponential(scale=2.0, size=500)
    curr = np.random.normal(loc=10.0, scale=1.0, size=500)

    stat, pval = drift_detector.calculate_ks_test(ref, curr)
    assert stat > 0.5
    assert pval < 1e-5


def test_evaluate_feature_drift_matrix():
    """Verifies feature-level evaluation across telemetry DataFrame."""
    np.random.seed(42)
    base_data = {feat: np.random.normal(100, 15, 200) for feat in NUMERICAL_FEATURES}
    curr_data = {feat: np.random.normal(100, 15, 200) for feat in NUMERICAL_FEATURES}

    # Artificially drift two features
    curr_data["port_entropy"] = np.random.normal(4.0, 0.2, 200)
    curr_data["failed_logins_window"] = np.random.poisson(8, 200)

    base_df = pd.DataFrame(base_data)
    curr_df = pd.DataFrame(curr_data)

    feature_results = drift_detector.evaluate_feature_drift(base_df, curr_df)
    assert len(feature_results) == len(NUMERICAL_FEATURES)
    assert "port_entropy" in feature_results
    assert feature_results["port_entropy"]["drift_detected"] is True


def test_evaluate_dataset_drift_aggregation():
    """Verifies aggregated dataset-level drift report structure and status."""
    np.random.seed(42)
    base_df = pd.DataFrame({feat: np.random.normal(50, 5, 200) for feat in NUMERICAL_FEATURES})
    # Stable current window
    stable_df = pd.DataFrame({feat: np.random.normal(50, 5, 200) for feat in NUMERICAL_FEATURES})

    stable_res = drift_detector.evaluate_dataset_drift(base_df, stable_df)
    assert stable_res["status"] == "STABLE"
    assert stable_res["drift_detected"] is False
    assert stable_res["drifted_features_count"] == 0

    # Critical drifted window
    drifted_df = pd.DataFrame({feat: np.random.normal(200, 50, 200) for feat in NUMERICAL_FEATURES})
    drift_res = drift_detector.evaluate_dataset_drift(base_df, drifted_df)
    assert drift_res["status"] == "CRITICAL"
    assert drift_res["drift_detected"] is True
    assert drift_res["max_psi"] >= 0.25
