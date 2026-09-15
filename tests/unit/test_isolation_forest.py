"""Unit tests for the Isolation Forest Anomaly Detector."""

import tempfile
import numpy as np
import pytest
from ml.models.isolation_forest.model import IsolationForestAnomalyDetector


@pytest.fixture
def trained_iso_forest() -> IsolationForestAnomalyDetector:
    """Trains an Isolation Forest on tightly clustered normal synthetic feature vectors."""
    np.random.seed(42)
    # 200 normal samples centered around mean=10, std=1
    normal_data = np.random.normal(loc=10.0, scale=1.0, size=(200, 14))
    detector = IsolationForestAnomalyDetector(n_estimators=100, contamination=0.05, random_state=42)
    detector.fit(normal_data)
    return detector


def test_isolation_forest_inlier_prediction(trained_iso_forest: IsolationForestAnomalyDetector):
    """Verifies that normal feature vectors within the distribution are scored as inliers."""
    normal_sample = np.random.normal(loc=10.0, scale=0.5, size=(1, 14))
    res = trained_iso_forest.score_single(normal_sample[0])
    assert res["is_anomaly"] is False
    assert res["anomaly_score"] < 0.55
    assert res["confidence"] >= 0.5


def test_isolation_forest_outlier_prediction(trained_iso_forest: IsolationForestAnomalyDetector):
    """Verifies that extreme outliers are detected as anomalies with high scores."""
    # Outlier far away from distribution (mean=100 vs baseline=10)
    outlier_sample = np.ones((1, 14)) * 100.0
    res = trained_iso_forest.score_single(outlier_sample[0])
    assert res["is_anomaly"] is True
    assert res["anomaly_score"] > 0.65
    assert res["confidence"] > 0.6


def test_isolation_forest_serialization(trained_iso_forest: IsolationForestAnomalyDetector):
    """Verifies saving and reloading Isolation Forest weights."""
    with tempfile.NamedTemporaryFile(suffix=".joblib") as tmp:
        trained_iso_forest.save(tmp.name)
        reloaded = IsolationForestAnomalyDetector.load(tmp.name)
        assert reloaded.is_fitted
        assert reloaded.contamination == trained_iso_forest.contamination

        sample = np.array([10.0] * 14)
        orig_res = trained_iso_forest.score_single(sample)
        reloaded_res = reloaded.score_single(sample)
        assert orig_res["anomaly_score"] == reloaded_res["anomaly_score"]

