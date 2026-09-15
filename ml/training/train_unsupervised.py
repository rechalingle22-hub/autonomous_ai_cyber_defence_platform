"""Training and validation pipeline for unsupervised anomaly detection models.

Trains:
1. Isolation Forest
2. PyTorch Deep Autoencoder

Saves artifacts to `ml/artifacts/` for live inference by the detection engine.
"""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from ml.datasets.synthetic_generator import synthetic_generator
from ml.preprocessing.pipeline import CybersecurityPreprocessor
from ml.models.isolation_forest.model import IsolationForestAnomalyDetector
from ml.models.autoencoder.model import AutoencoderAnomalyDetector

ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "artifacts")


def prepare_unsupervised_datasets():
    """Generates benign training set and mixed evaluation benchmark."""
    # Training: Exclusively benign telemetry to learn normal baseline
    benign_raw = synthetic_generator.generate_benign_traffic(count=400)
    train_df = pd.DataFrame([ev["features"] for ev in benign_raw])
    train_df["attack_category"] = "BENIGN"

    # Validation: Mix of benign and diverse attack scenarios
    val_benign = synthetic_generator.generate_benign_traffic(count=150)
    val_brute = synthetic_generator.generate_scenario_1_suspicious_auth(count=40)
    val_scan = synthetic_generator.generate_scenario_2_port_scan(count=40)
    val_exfil = synthetic_generator.generate_scenario_3_data_exfiltration(count=30)
    val_apt = synthetic_generator.generate_scenario_5_multistage_campaign()

    val_records = []
    for ev in val_benign + val_brute + val_scan + val_exfil + val_apt:
        row = ev["features"].copy()
        row["attack_category"] = ev["label"]
        val_records.append(row)

    val_df = pd.DataFrame(val_records)
    return train_df, val_df


def train_and_evaluate():
    """Executes unsupervised training, benchmark evaluation, and artifact serialization."""
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    print("=" * 60)
    print("AUTONOMOUS CYBER DEFENSE - UNSUPERVISED DETECTION TRAINING")
    print("=" * 60)

    # 1. Prepare Datasets
    print("\n[1/5] Generating baseline training telemetry and evaluation datasets...")
    train_df, val_df = prepare_unsupervised_datasets()
    print(f"  Training baseline samples (Benign): {len(train_df)}")
    print(f"  Validation samples (Mixed): {len(val_df)}")
    print(f"  Validation attack distribution:\n{val_df['attack_category'].value_counts().to_string()}")

    # 2. Fit Preprocessor strictly on training baseline
    print("\n[2/5] Fitting leakage-free preprocessor on training baseline...")
    preprocessor = CybersecurityPreprocessor()
    preprocessor.fit(train_df)
    prep_path = os.path.join(ARTIFACTS_DIR, "preprocessor.pkl")
    preprocessor.save(prep_path)
    print(f"  Preprocessor saved to: {prep_path}")

    X_train_scaled, _ = preprocessor.transform(train_df)
    X_val_scaled, _ = preprocessor.transform(val_df)
    y_val_binary = (val_df["attack_category"] != "BENIGN").astype(int).values

    # 3. Train Isolation Forest
    print("\n[3/5] Training Isolation Forest anomaly detector...")
    iso_forest = IsolationForestAnomalyDetector(n_estimators=150, contamination=0.03)
    iso_forest.fit(X_train_scaled)

    iso_preds, iso_scores, _ = iso_forest.predict_anomaly(X_val_scaled)
    iso_path = os.path.join(ARTIFACTS_DIR, "isolation_forest.joblib")
    iso_forest.save(iso_path)

    # 4. Train Deep Autoencoder
    print("\n[4/5] Training PyTorch Deep Autoencoder...")
    autoencoder = AutoencoderAnomalyDetector(input_dim=X_train_scaled.shape[1], latent_dim=8)
    autoencoder.fit(X_train_scaled, epochs=25, batch_size=32, lr=0.003, percentile_threshold=96.0)

    ae_preds, ae_scores, _ = autoencoder.predict_anomaly(X_val_scaled)
    ae_path = os.path.join(ARTIFACTS_DIR, "autoencoder.pt")
    autoencoder.save(ae_path)

    # 5. Evaluate Metrics
    print("\n[5/5] Evaluating detection metrics on holdout validation data:")
    print("-" * 60)
    for model_name, preds, scores in [
        ("Isolation Forest", iso_preds.astype(int), iso_scores),
        ("Deep Autoencoder", ae_preds.astype(int), ae_scores),
        ("Ensemble (Union)", (iso_preds | ae_preds).astype(int), (iso_scores + ae_scores) / 2.0),
    ]:
        p = precision_score(y_val_binary, preds, zero_division=0)
        r = recall_score(y_val_binary, preds, zero_division=0)
        f1 = f1_score(y_val_binary, preds, zero_division=0)
        auc = roc_auc_score(y_val_binary, scores)
        print(f"{model_name:20s} | Precision: {p:.4f} | Recall: {r:.4f} | F1: {f1:.4f} | ROC-AUC: {auc:.4f}")
    print("-" * 60)

    print("\nUnsupervised training complete! Artifacts ready in:", ARTIFACTS_DIR)
    return {
        "preprocessor_path": prep_path,
        "isolation_forest_path": iso_path,
        "autoencoder_path": ae_path,
    }


if __name__ == "__main__":
    train_and_evaluate()
