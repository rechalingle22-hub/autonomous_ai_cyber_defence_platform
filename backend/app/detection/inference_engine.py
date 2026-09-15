"""Comprehensive Multi-Model Detection & Classification Inference Engine.

Integrates:
1. Unsupervised Anomaly Detectors: Isolation Forest & PyTorch Deep Autoencoder
2. Supervised Attack Classifiers: XGBoost & Random Forest
3. Explainable AI (XAI): SHAP TreeExplainer local feature attribution
"""

import os
import time
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from ml.preprocessing.pipeline import CybersecurityPreprocessor
from ml.models.isolation_forest.model import IsolationForestAnomalyDetector
from ml.models.autoencoder.model import AutoencoderAnomalyDetector
from ml.models.random_forest.model import RandomForestAttackClassifier
from ml.models.xgboost.model import XGBoostAttackClassifier
from ml.explainability.shap_explainer import ModelExplainer
from ml.features.definitions import NUMERICAL_FEATURES, FEATURE_DEFAULTS

ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ml/artifacts"))


class HybridDetectionInferenceEngine:
    """Unified engine coordinating anomaly detection, attack classification, and XAI attribution."""

    def __init__(self, artifacts_dir: str = ARTIFACTS_DIR) -> None:
        self.artifacts_dir = artifacts_dir
        self.preprocessor: Optional[CybersecurityPreprocessor] = None
        self.isolation_forest: Optional[IsolationForestAnomalyDetector] = None
        self.autoencoder: Optional[AutoencoderAnomalyDetector] = None
        self.random_forest: Optional[RandomForestAttackClassifier] = None
        self.xgboost: Optional[XGBoostAttackClassifier] = None
        self.explainer: Optional[ModelExplainer] = None
        self.is_ready: bool = False
        self._load_models()

    def _load_models(self) -> None:
        """Loads serialized model artifacts from disk."""
        prep_path = os.path.join(self.artifacts_dir, "preprocessor.pkl")
        iso_path = os.path.join(self.artifacts_dir, "isolation_forest.joblib")
        ae_path = os.path.join(self.artifacts_dir, "autoencoder.pt")
        rf_path = os.path.join(self.artifacts_dir, "random_forest.joblib")
        xgb_path = os.path.join(self.artifacts_dir, "xgboost.joblib")

        try:
            if os.path.exists(prep_path) and os.path.exists(iso_path) and os.path.exists(ae_path):
                self.preprocessor = CybersecurityPreprocessor.load(prep_path)
                self.isolation_forest = IsolationForestAnomalyDetector.load(iso_path)
                self.autoencoder = AutoencoderAnomalyDetector.load(ae_path)

                if os.path.exists(rf_path):
                    self.random_forest = RandomForestAttackClassifier.load(rf_path)
                if os.path.exists(xgb_path):
                    self.xgboost = XGBoostAttackClassifier.load(xgb_path)
                    self.explainer = ModelExplainer(self.xgboost)

                self.is_ready = True
        except Exception:
            self.is_ready = False

    def ensure_models_ready(self) -> None:
        """Auto-trains models if any artifact is missing."""
        if not self.is_ready or self.xgboost is None:
            from ml.training.train_unsupervised import train_and_evaluate
            from ml.training.train_supervised import train_and_evaluate_supervised
            train_and_evaluate()
            train_and_evaluate_supervised()
            self._load_models()

    def analyze_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Performs full dual-layer evaluation: Anomaly scoring, Attack classification, and SHAP XAI."""
        self.ensure_models_ready()
        t0 = time.perf_counter()

        features_dict = event_data.get("features", {})
        full_row = {}
        for feat in NUMERICAL_FEATURES:
            full_row[feat] = float(features_dict.get(feat, FEATURE_DEFAULTS.get(feat, 0.0)))

        # Automatically compute consistent flow ratios if not explicitly supplied
        if "fwd_packet_length_mean" not in features_dict:
            full_row["fwd_packet_length_mean"] = full_row["total_fwd_bytes"] / max(1.0, full_row["total_fwd_packets"])
        if "bwd_packet_length_mean" not in features_dict:
            full_row["bwd_packet_length_mean"] = full_row["total_bwd_bytes"] / max(1.0, full_row["total_bwd_packets"])
        if "flow_packets_per_sec" not in features_dict:
            dur_s = max(0.001, full_row["flow_duration_ms"] / 1000.0)
            full_row["flow_packets_per_sec"] = (full_row["total_fwd_packets"] + full_row["total_bwd_packets"]) / dur_s
        if "flow_iat_mean" not in features_dict:
            tot_pkts = full_row["total_fwd_packets"] + full_row["total_bwd_packets"]
            full_row["flow_iat_mean"] = full_row["flow_duration_ms"] / max(1.0, tot_pkts)

        df_row = pd.DataFrame([full_row])
        X_scaled, _ = self.preprocessor.transform(df_row)

        # 1. Unsupervised Anomaly Detectors
        iso_res = self.isolation_forest.score_single(X_scaled[0])
        ae_res = self.autoencoder.score_single(X_scaled[0])
        composite_anomaly_score = float(np.round(0.5 * iso_res["anomaly_score"] + 0.5 * ae_res["anomaly_score"], 4))

        # 2. Supervised Attack Classifiers
        xgb_res = (
            self.xgboost.score_single(X_scaled[0])
            if self.xgboost
            else {"attack_type": "BENIGN", "confidence": 0.5}
        )
        rf_res = (
            self.random_forest.score_single(X_scaled[0])
            if self.random_forest
            else {"attack_type": "BENIGN", "confidence": 0.5}
        )

        # Classification consensus: XGBoost + Random Forest ensemble
        xgb_attack = str(xgb_res["attack_type"])
        xgb_conf = float(xgb_res["confidence"])
        rf_attack = str(rf_res["attack_type"])
        rf_conf = float(rf_res["confidence"])

        if xgb_attack != "BENIGN" and xgb_conf >= 0.5:
            attack_type = xgb_attack
            confidence = xgb_conf
            is_attack = True
        elif rf_attack != "BENIGN" and rf_conf >= 0.55:
            attack_type = rf_attack
            confidence = rf_conf
            is_attack = True
        elif xgb_attack != "BENIGN" and rf_attack == xgb_attack:
            attack_type = xgb_attack
            confidence = max(xgb_conf, rf_conf)
            is_attack = True
        else:
            attack_type = "BENIGN"
            benign_prob = float(xgb_res.get("class_probabilities", {}).get("BENIGN", 0.5))
            confidence = max(benign_prob, rf_conf if rf_attack == "BENIGN" else 0.5)
            is_attack = False

        is_anomaly = composite_anomaly_score >= 0.65 or (iso_res["is_anomaly"] and ae_res["is_anomaly"])

        if is_attack:
            prediction = "suspicious"
            final_attack_type = attack_type
        elif is_anomaly:
            prediction = "suspicious"
            final_attack_type = "ANOMALOUS_OTHER"
            confidence = max(confidence, composite_anomaly_score)
        else:
            prediction = "benign"
            final_attack_type = "BENIGN"

        confidence = float(np.round(confidence, 4))

        # Severity Mapping
        if prediction == "suspicious":
            if composite_anomaly_score >= 0.85 or final_attack_type in ["DATA_EXFILTRATION", "DOS_DDOS"]:
                severity = "CRITICAL"
            elif composite_anomaly_score >= 0.65 or final_attack_type in ["BRUTE_FORCE", "WEB_ATTACK"]:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
        else:
            severity = "LOW" if composite_anomaly_score < 0.35 else "MEDIUM"

        # 3. Explainable AI (SHAP)
        xai_data = {}
        if self.explainer and self.xgboost:
            try:
                class_names = [str(c) for c in self.xgboost.classes_]
                target_cat = final_attack_type if final_attack_type in class_names else "BENIGN"
                pred_idx = class_names.index(target_cat) if target_cat in class_names else 0
                xai_data = self.explainer.explain_prediction(
                    X_scaled[0],
                    predicted_class_idx=pred_idx,
                    predicted_category=final_attack_type,
                    raw_feature_values=full_row,
                    top_k=4,
                )
            except Exception:
                xai_data = {
                    "predicted_category": final_attack_type,
                    "contributing_factors": [],
                    "deterministic_summary": f"Classified as {final_attack_type} based on telemetry patterns.",
                    "explanation_method": "Heuristic",
                }

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "event_id": event_data.get("event_id", "unknown"),
            "prediction": prediction,
            "attack_type": final_attack_type,
            "confidence": confidence,
            "anomaly_score": composite_anomaly_score,
            "severity": severity,
            "model_used": "XGBOOST_ENSEMBLE",
            "latency_ms": round(latency_ms, 3),
            "xai_explanation": xai_data,
            "detectors": {
                "xgboost": xgb_res,
                "random_forest": rf_res,
                "isolation_forest": iso_res,
                "autoencoder": ae_res,
            },
        }

    def analyze_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch evaluation across multiple events."""
        return [self.analyze_event(ev) for ev in events]


# Backward compatibility alias
UnsupervisedInferenceEngine = HybridDetectionInferenceEngine

# Global unified inference engine instance
inference_engine = HybridDetectionInferenceEngine()
