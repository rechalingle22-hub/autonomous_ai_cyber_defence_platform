"""Unit tests for PyTorch Deep Autoencoder Anomaly Detector."""

import tempfile
import numpy as np
import torch
import pytest
from ml.models.autoencoder.model import AutoencoderAnomalyDetector, AutoencoderNet


def test_autoencoder_architecture_dimensions():
    """Verifies that the PyTorch Autoencoder forward pass retains tensor shape."""
    net = AutoencoderNet(input_dim=14, latent_dim=8)
    dummy_input = torch.randn(10, 14)
    reconstructed = net(dummy_input)
    assert reconstructed.shape == (10, 14)


def test_autoencoder_training_and_anomaly_scoring():
    """Verifies that autoencoder learns normal pattern and assigns higher error to anomalies."""
    np.random.seed(42)
    torch.manual_seed(42)

    # 150 normal samples
    normal_data = np.random.normal(loc=5.0, scale=0.8, size=(150, 14)).astype(np.float32)

    detector = AutoencoderAnomalyDetector(input_dim=14, latent_dim=8, device="cpu")
    detector.fit(normal_data, epochs=15, batch_size=32, lr=0.005)
    assert detector.is_fitted
    assert detector.threshold > 0.0

    # Normal sample test
    normal_test = np.random.normal(loc=5.0, scale=0.5, size=(5, 14)).astype(np.float32)
    is_anom, scores, _ = detector.predict_anomaly(normal_test)
    assert np.mean(scores) < 0.60

    # Strong anomaly test (value 80 vs baseline 5)
    anomaly_sample = np.ones((5, 14), dtype=np.float32) * 80.0
    is_anom_out, scores_out, _ = detector.predict_anomaly(anomaly_sample)
    assert bool(is_anom_out.all()) is True
    assert np.mean(scores_out) > 0.70


def test_autoencoder_serialization():
    """Verifies saving and loading PyTorch Autoencoder weights."""
    np.random.seed(42)
    data = np.random.normal(loc=2.0, scale=0.5, size=(100, 14)).astype(np.float32)
    detector = AutoencoderAnomalyDetector(input_dim=14, device="cpu")
    detector.fit(data, epochs=5, batch_size=32)

    with tempfile.NamedTemporaryFile(suffix=".pt") as tmp:
        detector.save(tmp.name)
        reloaded = AutoencoderAnomalyDetector.load(tmp.name, device="cpu")
        assert reloaded.is_fitted
        assert reloaded.threshold == detector.threshold

        test_vec = np.array([2.0] * 14, dtype=np.float32)
        orig = detector.score_single(test_vec)
        loaded = reloaded.score_single(test_vec)
        assert orig["anomaly_score"] == loaded["anomaly_score"]

