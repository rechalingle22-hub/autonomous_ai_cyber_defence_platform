"""Explainable AI (XAI) Subsystem using SHAP TreeExplainer.

Calculates mathematically rigorous Shapley values for individual telemetry predictions,
answering exactly why an event was classified as a specific attack category.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import shap
from ml.features.definitions import NUMERICAL_FEATURES, ATTACK_CATEGORIES

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "flow_duration_ms": "Connection duration and persistence window",
    "total_fwd_packets": "Volume of transmitted forward packets",
    "total_bwd_packets": "Volume of received response packets",
    "total_fwd_bytes": "Total outbound payload bytes transferred",
    "total_bwd_bytes": "Total inbound response bytes received",
    "fwd_packet_length_mean": "Average size of outbound packet payloads",
    "bwd_packet_length_mean": "Average size of inbound response packets",
    "flow_bytes_per_sec": "High-velocity data transmission rate",
    "flow_packets_per_sec": "Rapid burst connection frequency",
    "flow_iat_mean": "Inter-arrival packet timing consistency",
    "destination_port": "Target destination network service port",
    "failed_logins_window": "Rate of failed authentication attempts in sliding window",
    "port_entropy": "Spread and dispersion of probed destination ports",
    "bytes_out_ratio": "Asymmetric outbound vs inbound data transfer ratio",
}


class ModelExplainer:
    """Computes SHAP feature importance attributions for tree-based attack classifiers."""

    def __init__(
        self,
        model: Any,
        feature_names: Optional[List[str]] = None,
        class_names: Optional[List[str]] = None,
    ) -> None:
        self.feature_names = feature_names or NUMERICAL_FEATURES
        self.class_names = class_names or getattr(model, "classes_", list(ATTACK_CATEGORIES))
        self.underlying_model = getattr(model, "model", model)
        self.explainer = shap.TreeExplainer(self.underlying_model)

    def explain_prediction(
        self,
        feature_vector: np.ndarray,
        predicted_class_idx: int,
        predicted_category: Optional[str] = None,
        raw_feature_values: Optional[Dict[str, float]] = None,
        top_k: int = 4,
    ) -> Dict[str, Any]:
        """Calculates Shapley values for a specific prediction and returns top contributing factors."""
        X = feature_vector.reshape(1, -1) if feature_vector.ndim == 1 else feature_vector

        # Calculate SHAP values
        raw_shap = self.explainer.shap_values(X)

        # Handle multi-class output format in SHAP
        if isinstance(raw_shap, list):
            # List of arrays [class_0_shap, class_1_shap, ...]
            class_idx = min(predicted_class_idx, len(raw_shap) - 1)
            sample_shap = raw_shap[class_idx][0]
        elif raw_shap.ndim == 3:
            # 3D array: (samples, features, classes)
            class_idx = min(predicted_class_idx, raw_shap.shape[2] - 1)
            sample_shap = raw_shap[0, :, class_idx]
        else:
            # Binary or single output (samples, features)
            sample_shap = raw_shap[0]

        # Rank features by absolute magnitude
        top_indices = np.argsort(np.abs(sample_shap))[::-1][:top_k]

        contributing_factors: List[Dict[str, Any]] = []
        explanation_bullet_points: List[str] = []

        for rank, idx in enumerate(top_indices, start=1):
            feat_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            shap_val = float(np.round(sample_shap[idx], 4))
            raw_val = (
                raw_feature_values.get(feat_name, float(X[0, idx]))
                if raw_feature_values
                else float(X[0, idx])
            )
            desc = FEATURE_DESCRIPTIONS.get(feat_name, "Network flow feature")

            direction = "INCREASED_RISK" if shap_val > 0 else "DECREASED_RISK"
            sign = "+" if shap_val > 0 else ""

            contributing_factors.append({
                "rank": rank,
                "feature": feat_name,
                "raw_value": round(float(raw_val), 2),
                "shap_attribution": shap_val,
                "impact": direction,
                "description": desc,
            })

            explanation_bullet_points.append(
                f"{rank}. {feat_name} ({sign}{shap_val}) — {desc}"
            )

        if predicted_category is not None:
            predicted_label = predicted_category
        elif self.class_names and predicted_class_idx < len(self.class_names):
            predicted_label = str(self.class_names[predicted_class_idx])
        elif predicted_class_idx < len(ATTACK_CATEGORIES):
            predicted_label = ATTACK_CATEGORIES[predicted_class_idx]
        else:
            predicted_label = "ANOMALOUS_OTHER"

        deterministic_summary = (
            f"Prediction of '{predicted_label}' was primarily driven by: "
            + "; ".join(explanation_bullet_points)
        )

        return {
            "predicted_category": predicted_label,
            "contributing_factors": contributing_factors,
            "deterministic_summary": deterministic_summary,
            "explanation_method": "TreeSHAP",
        }

