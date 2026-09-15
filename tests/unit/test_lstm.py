"""Unit tests for PyTorch LSTM Sequence Attack Detector."""

import os
import tempfile
import numpy as np
import pytest
from ml.models.lstm.model import LSTMSequenceAttackDetector


def test_lstm_sequence_creation():
    """Tests temporal sliding window creation."""
    X = np.arange(50).reshape(10, 5).astype(np.float32)
    y = np.array([0, 0, 0, 1, 1, 0, 0, 1, 1, 0])

    detector = LSTMSequenceAttackDetector(input_dim=5, hidden_dim=16, seq_length=3)
    X_seqs, y_seqs = detector.create_sequences(X, y)

    # 10 samples with seq_length 3 yields 10 - 3 + 1 = 8 windows
    assert X_seqs.shape == (8, 3, 5)
    assert y_seqs.shape == (8,)
    # Verify label corresponds to final timestep of window
    assert y_seqs[0] == y[2]
    assert y_seqs[-1] == y[-1]


def test_lstm_fit_and_predict():
    """Tests training and sequence prediction with LSTM."""
    np.random.seed(42)
    n_samples = 80
    n_features = 14
    X = np.random.randn(n_samples, n_features).astype(np.float32)
    classes = ["BENIGN", "DOS_DDOS", "PORT_SCAN"]
    y = np.random.choice([0, 1, 2], size=n_samples)

    detector = LSTMSequenceAttackDetector(
        input_dim=n_features,
        hidden_dim=32,
        seq_length=4,
        device="cpu",
    )
    detector.fit(X, y, epochs=5, batch_size=16, classes=classes)

    assert detector.is_fitted
    assert detector.classes_ == classes

    # Test scoring with recent event history
    recent_history = X[:10]
    result = detector.score_single_event_with_history(recent_history)

    assert "attack_type" in result
    assert result["attack_type"] in classes
    assert "confidence" in result
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["model"] == "LSTM_SEQUENCE"


def test_lstm_serialization():
    """Tests checkpoint save and reload for LSTM."""
    np.random.seed(42)
    X = np.random.randn(50, 14).astype(np.float32)
    classes = ["BENIGN", "BRUTE_FORCE"]
    y = np.random.choice([0, 1], size=50)

    detector = LSTMSequenceAttackDetector(
        input_dim=14,
        hidden_dim=16,
        seq_length=3,
        device="cpu",
    )
    detector.fit(X, y, epochs=3, batch_size=16, classes=classes)

    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        detector.save(tmp_path)
        assert os.path.exists(tmp_path)

        loaded_detector = LSTMSequenceAttackDetector.load(tmp_path, device="cpu")
        assert loaded_detector.is_fitted
        assert loaded_detector.classes_ == classes

        res_orig = detector.score_single_event_with_history(X[:5])
        res_loaded = loaded_detector.score_single_event_with_history(X[:5])
        assert res_orig["attack_type"] == res_loaded["attack_type"]
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

