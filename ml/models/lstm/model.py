"""PyTorch LSTM Sequence Attack Detector.

Processes chronological sliding windows of telemetry feature vectors to detect
multi-stage attacks, reconnaissance sweeps, and temporal attack progressions.
"""

import os
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from ml.features.definitions import ATTACK_CATEGORIES


class LSTMNet(nn.Module):
    """2-Layer Recurrent LSTM for temporal event sequence classification."""

    def __init__(
        self,
        input_dim: int = 14,
        hidden_dim: int = 64,
        num_classes: int = len(ATTACK_CATEGORIES),
        num_layers: int = 2,
    ) -> None:
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1 if num_layers > 1 else 0.0,
        )
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.1),
            nn.Linear(32, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: (batch_size, seq_len, input_dim)
        lstm_out, _ = self.lstm(x)
        # Take representation from final time-step
        last_timestep = lstm_out[:, -1, :]
        logits = self.fc(last_timestep)
        return logits


class LSTMSequenceAttackDetector:
    """High-level wrapper for training and predicting with PyTorch LSTM."""

    def __init__(
        self,
        input_dim: int = 14,
        hidden_dim: int = 64,
        seq_length: int = 5,
        num_classes: int = len(ATTACK_CATEGORIES),
        device: Optional[str] = None,
    ) -> None:
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.seq_length = seq_length
        self.num_classes = num_classes
        self.classes_ = list(ATTACK_CATEGORIES)

        if device is None:
            self.device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        self.model = LSTMNet(
            input_dim=self.input_dim,
            hidden_dim=self.hidden_dim,
            num_classes=self.num_classes,
        ).to(self.device)
        self.is_fitted: bool = False

    def create_sequences(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Converts 2D feature matrix into 3D sliding sequence windows."""
        num_samples = len(X)
        if num_samples < self.seq_length:
            # Pad with repeated earliest sample
            pad_needed = self.seq_length - num_samples
            pad = np.repeat(X[0:1], pad_needed, axis=0)
            X = np.vstack([pad, X])
            num_samples = len(X)

        X_seqs = []
        y_seqs = []
        for i in range(num_samples - self.seq_length + 1):
            X_seqs.append(X[i : i + self.seq_length])
            if y is not None:
                # Label is the category of the final event in the window
                y_seqs.append(y[i + self.seq_length - 1])

        return np.array(X_seqs), np.array(y_seqs) if y is not None else None

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        epochs: int = 15,
        batch_size: int = 32,
        lr: float = 0.004,
        classes: Optional[List[str]] = None,
    ) -> "LSTMSequenceAttackDetector":
        """Trains the LSTM on sequential windows of telemetry."""
        if classes:
            self.classes_ = list(classes)
        self.num_classes = len(self.classes_) if self.classes_ else len(np.unique(y_train))
        self.model = LSTMNet(
            input_dim=self.input_dim,
            hidden_dim=self.hidden_dim,
            num_classes=self.num_classes,
        ).to(self.device)

        X_seqs, y_seqs = self.create_sequences(X_train, y_train)

        tensor_x = torch.tensor(X_seqs, dtype=torch.float32)
        tensor_y = torch.tensor(y_seqs, dtype=torch.long)
        dataset = TensorDataset(tensor_x, tensor_y)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-4)
        criterion = nn.CrossEntropyLoss()

        self.model.train()
        for epoch in range(epochs):
            for batch_x, batch_y in loader:
                bx = batch_x.to(self.device)
                by = batch_y.to(self.device)

                optimizer.zero_grad()
                outputs = self.model(bx)
                loss = criterion(outputs, by)
                loss.backward()
                optimizer.step()

        self.is_fitted = True
        return self

    def predict(self, X_seq: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Inference on 3D sequence array (batch_size, seq_length, input_dim)."""
        if not self.is_fitted:
            raise RuntimeError("LSTM must be fitted before predict()")

        self.model.eval()
        tensor_x = torch.tensor(X_seq, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            logits = self.model(tensor_x)
            probs = torch.softmax(logits, dim=1).cpu().numpy()

        pred_indices = np.argmax(probs, axis=1)
        confidence = np.max(probs, axis=1)
        return pred_indices, confidence, probs

    def score_single_event_with_history(self, recent_history: np.ndarray) -> Dict[str, Any]:
        """Scores the latest event using its recent sliding window context."""
        X_seq, _ = self.create_sequences(recent_history)
        if len(X_seq) == 0:
            X_seq = np.expand_dims(recent_history[-self.seq_length:], axis=0)

        pred_idx, conf, probs = self.predict(X_seq[-1:])
        class_idx = int(pred_idx[0])
        class_name = self.classes_[class_idx] if class_idx < len(self.classes_) else "ANOMALOUS_OTHER"

        return {
            "attack_type": class_name,
            "confidence": float(np.round(conf[0], 4)),
            "model": "LSTM_SEQUENCE",
        }

    def save(self, filepath: str) -> None:
        """Serializes LSTM model checkpoint."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        checkpoint = {
            "state_dict": self.model.state_dict(),
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "seq_length": self.seq_length,
            "num_classes": self.num_classes,
            "classes_": self.classes_,
            "is_fitted": self.is_fitted,
        }
        torch.save(checkpoint, filepath)

    @classmethod
    def load(cls, filepath: str, device: Optional[str] = None) -> "LSTMSequenceAttackDetector":
        """Loads LSTM weights and hyperparameters from disk."""
        checkpoint = torch.load(filepath, map_location="cpu", weights_only=False)
        detector = cls(
            input_dim=checkpoint["input_dim"],
            hidden_dim=checkpoint["hidden_dim"],
            seq_length=checkpoint["seq_length"],
            num_classes=checkpoint["num_classes"],
            device=device,
        )
        detector.model.load_state_dict(checkpoint["state_dict"])
        detector.classes_ = checkpoint["classes_"]
        detector.is_fitted = checkpoint["is_fitted"]
        detector.model.eval()
        return detector

