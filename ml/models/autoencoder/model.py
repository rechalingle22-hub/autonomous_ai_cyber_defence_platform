"""Deep Autoencoder Neural Network for Unsupervised Telemetry Anomaly Detection.

Implements deep reconstruction loss in PyTorch to identify novel intrusions,
zero-day anomalous behavior, and out-of-distribution telemetry patterns.
"""

import os
from typing import Dict, Any, Tuple, Optional
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset


class AutoencoderNet(nn.Module):
    """PyTorch Deep Autoencoder neural network with bottleneck representation."""

    def __init__(self, input_dim: int, latent_dim: int = 8) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.LayerNorm(64),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.05),
            nn.Linear(64, 32),
            nn.LayerNorm(32),
            nn.LeakyReLU(0.2),
            nn.Linear(32, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.LayerNorm(32),
            nn.LeakyReLU(0.2),
            nn.Linear(32, 64),
            nn.LayerNorm(64),
            nn.LeakyReLU(0.2),
            nn.Linear(64, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AutoencoderAnomalyDetector:
    """High-level estimator wrapper for PyTorch Deep Autoencoder."""

    def __init__(
        self,
        input_dim: int = 14,
        latent_dim: int = 8,
        device: Optional[str] = None,
    ) -> None:
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        if device is None:
            self.device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        self.model = AutoencoderNet(input_dim=self.input_dim, latent_dim=self.latent_dim).to(self.device)
        self.threshold: float = 1.0
        self.min_loss: float = 0.0
        self.max_loss: float = 2.0
        self.is_fitted: bool = False

    def fit(
        self,
        X_train: np.ndarray,
        epochs: int = 20,
        batch_size: int = 32,
        lr: float = 0.003,
        percentile_threshold: float = 97.0,
    ) -> "AutoencoderAnomalyDetector":
        """Trains the autoencoder on normal/benign telemetry and computes detection threshold."""
        self.input_dim = X_train.shape[1]
        self.model = AutoencoderNet(input_dim=self.input_dim, latent_dim=self.latent_dim).to(self.device)

        tensor_x = torch.tensor(X_train, dtype=torch.float32)
        dataset = TensorDataset(tensor_x)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-4)
        criterion = nn.MSELoss()

        self.model.train()
        for epoch in range(epochs):
            for batch in loader:
                inputs = batch[0].to(self.device)
                optimizer.zero_grad()
                outputs = self.model(inputs)
                loss = criterion(outputs, inputs)
                loss.backward()
                optimizer.step()

        # Compute per-sample reconstruction errors on training baseline to calibrate threshold
        self.model.eval()
        with torch.no_grad():
            inputs = tensor_x.to(self.device)
            reconstructed = self.model(inputs)
            # Element-wise MSE per sample
            sample_losses = torch.mean((inputs - reconstructed) ** 2, dim=1).cpu().numpy()

        self.threshold = float(np.percentile(sample_losses, percentile_threshold))
        self.min_loss = float(np.min(sample_losses))
        self.max_loss = float(np.percentile(sample_losses, 99.5))
        self.is_fitted = True
        return self

    def predict_anomaly(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Calculates reconstruction errors and classifies samples as normal or anomalous."""
        if not self.is_fitted:
            raise RuntimeError("Autoencoder must be fitted before predict_anomaly()")

        self.model.eval()
        tensor_x = torch.tensor(X, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            reconstructed = self.model(tensor_x)
            sample_losses = torch.mean((tensor_x - reconstructed) ** 2, dim=1).cpu().numpy()

        is_anomaly = sample_losses > self.threshold

        # Normalize score into [0.0, 1.0] relative to threshold
        # Score = 0.5 at the threshold, >0.5 for anomalies, <0.5 for inliers
        denom = max(1e-5, (self.max_loss - self.min_loss))
        linear_score = np.clip((sample_losses - self.min_loss) / denom, 0.0, 1.0)

        # Non-linear sigmoid enhancement around the threshold
        relative_to_threshold = (sample_losses - self.threshold) / max(1e-4, self.threshold)
        anomaly_score = 1.0 / (1.0 + np.exp(-3.0 * relative_to_threshold))

        confidence = np.clip(np.abs(anomaly_score - 0.5) * 2.0, 0.5, 0.99)

        return is_anomaly, anomaly_score, confidence

    def score_single(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Convenience evaluation for single event feature vector."""
        X = feature_vector.reshape(1, -1) if feature_vector.ndim == 1 else feature_vector
        is_anom, scores, conf = self.predict_anomaly(X)
        return {
            "is_anomaly": bool(is_anom[0]),
            "anomaly_score": float(np.round(scores[0], 4)),
            "confidence": float(np.round(conf[0], 4)),
            "model": "AUTOENCODER",
        }

    def save(self, filepath: str) -> None:
        """Serializes PyTorch model weights and threshold metadata."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        checkpoint = {
            "state_dict": self.model.state_dict(),
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "threshold": self.threshold,
            "min_loss": self.min_loss,
            "max_loss": self.max_loss,
            "is_fitted": self.is_fitted,
        }
        torch.save(checkpoint, filepath)

    @classmethod
    def load(cls, filepath: str, device: Optional[str] = None) -> "AutoencoderAnomalyDetector":
        """Loads model weights and calibration threshold from disk."""
        checkpoint = torch.load(filepath, map_location="cpu", weights_only=False)
        detector = cls(
            input_dim=checkpoint["input_dim"],
            latent_dim=checkpoint["latent_dim"],
            device=device,
        )
        detector.model.load_state_dict(checkpoint["state_dict"])
        detector.threshold = checkpoint["threshold"]
        detector.min_loss = checkpoint["min_loss"]
        detector.max_loss = checkpoint["max_loss"]
        detector.is_fitted = checkpoint["is_fitted"]
        detector.model.eval()
        return detector

