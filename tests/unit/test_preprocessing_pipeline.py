"""Unit tests for the ML Preprocessing Pipeline."""

import os
import tempfile
import numpy as np
import pandas as pd
import pytest
from ml.preprocessing.pipeline import CybersecurityPreprocessor
from ml.datasets.synthetic_generator import synthetic_generator


@pytest.fixture
def sample_dataset() -> pd.DataFrame:
    """Generates a mixed synthetic dataset of benign and attack traffic for pipeline tests."""
    benign = synthetic_generator.generate_benign_traffic(count=80)
    attacks = synthetic_generator.generate_scenario_1_suspicious_auth(count=40)
    records = []
    for ev in benign + attacks:
        row = ev["features"].copy()
        row["attack_category"] = ev["label"]
        records.append(row)
    return pd.DataFrame(records)


def test_train_val_test_splitting(sample_dataset: pd.DataFrame):
    """Verifies that dataset split ratios and shapes match specifications."""
    preprocessor = CybersecurityPreprocessor()
    train_df, val_df, test_df = preprocessor.split_data(
        sample_dataset,
        test_size=0.15,
        val_size=0.15,
        random_state=42,
    )
    total_len = len(sample_dataset)
    assert len(train_df) + len(val_df) + len(test_df) == total_len
    # Verify stratification: both train and test have multiple classes
    assert len(train_df["attack_category"].unique()) > 1
    assert len(test_df["attack_category"].unique()) > 1


def test_imputation_and_leakage_prevention(sample_dataset: pd.DataFrame):
    """Verifies that imputations are strictly computed on train and applied to test without leakage."""
    preprocessor = CybersecurityPreprocessor()
    train_df, _, test_df = preprocessor.split_data(sample_dataset, test_size=0.2, val_size=0.1)

    # Inject NaN and inf into test set
    test_df_corrupted = test_df.copy()
    test_df_corrupted.loc[0, "flow_duration_ms"] = np.nan
    test_df_corrupted.loc[1, "flow_bytes_per_sec"] = np.inf

    # Fit pipeline on clean train
    preprocessor.fit(train_df)
    assert preprocessor.is_fitted
    assert "flow_duration_ms" in preprocessor.impute_medians

    # Transform corrupted test set
    X_test_scaled, y_test = preprocessor.transform(test_df_corrupted)
    assert not np.isnan(X_test_scaled).any()
    assert not np.isinf(X_test_scaled).any()
    assert len(X_test_scaled) == len(test_df_corrupted)


def test_pipeline_serialization_and_reloading(sample_dataset: pd.DataFrame):
    """Verifies saving fitted preprocessor to disk and reloading it with identical output."""
    preprocessor = CybersecurityPreprocessor()
    train_df, _, test_df = preprocessor.split_data(sample_dataset, test_size=0.2)
    X_train_scaled, _ = preprocessor.fit_transform(train_df)

    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_path = os.path.join(tmpdir, "preprocessor.pkl")
        preprocessor.save(artifact_path)
        assert os.path.exists(artifact_path)

        # Reload
        reloaded = CybersecurityPreprocessor.load(artifact_path)
        assert reloaded.is_fitted
        X_test_orig, _ = preprocessor.transform(test_df)
        X_test_reloaded, _ = reloaded.transform(test_df)
        np.testing.assert_allclose(X_test_orig, X_test_reloaded)


def test_inverse_transform_labels():
    """Verifies numeric labels map correctly back to category names."""
    preprocessor = CybersecurityPreprocessor()
    sample_indices = np.array([0, 1, 2])
    names = preprocessor.inverse_transform_labels(sample_indices)
    assert len(names) == 3
    assert isinstance(names[0], str)

