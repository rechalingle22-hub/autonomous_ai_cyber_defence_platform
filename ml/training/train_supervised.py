"""Supervised Multi-Class Attack Classification Training Pipeline.

Trains:
1. Random Forest Classifier
2. XGBoost Multi-Class Gradient Boosted Trees
3. PyTorch LSTM Sequence Model
4. TreeSHAP Feature Attribution Explainer

Evaluates metrics and persists production artifacts to `ml/artifacts/`.
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
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from ml.datasets.synthetic_generator import synthetic_generator
from ml.preprocessing.pipeline import CybersecurityPreprocessor
from ml.models.random_forest.model import RandomForestAttackClassifier
from ml.models.xgboost.model import XGBoostAttackClassifier
from ml.models.lstm.model import LSTMSequenceAttackDetector
from ml.explainability.shap_explainer import ModelExplainer
from ml.features.definitions import ATTACK_CATEGORIES

ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../artifacts"))


def build_supervised_dataset() -> pd.DataFrame:
    """Compiles a balanced multi-class dataset across standard attack categories."""
    benign = synthetic_generator.generate_benign_traffic(count=450)
    brute = synthetic_generator.generate_scenario_1_suspicious_auth(count=120)
    scan = synthetic_generator.generate_scenario_2_port_scan(count=120)
    exfil = synthetic_generator.generate_scenario_3_data_exfiltration(count=90)
    suspicious = synthetic_generator.generate_scenario_4_compromised_account(count=60)
    apt = synthetic_generator.generate_scenario_5_multistage_campaign()

    records = []
    for ev in benign + brute + scan + exfil + suspicious + apt:
        row = ev["features"].copy()
        row["attack_category"] = ev["label"]
        records.append(row)

    df = pd.DataFrame(records)
    return df.sample(frac=1.0, random_state=42).reset_index(drop=True)


def train_and_evaluate_supervised():
    """Executes the complete supervised training, evaluation, and XAI pipeline."""
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    print("=" * 65)
    print("AUTONOMOUS CYBER DEFENSE - SUPERVISED ATTACK CLASSIFICATION")
    print("=" * 65)

    # 1. Dataset Generation & Splitting
    print("\n[1/6] Compiling multi-class dataset and performing stratified split...")
    dataset = build_supervised_dataset()
    print(f"  Total samples compiled: {len(dataset)}")
    print(f"  Class breakdown:\n{dataset['attack_category'].value_counts().to_string()}")

    preprocessor = CybersecurityPreprocessor()
    train_df, val_df, test_df = preprocessor.split_data(dataset, test_size=0.15, val_size=0.15, random_state=42)
    print(f"  Splits -> Train: {len(train_df)} | Val: {len(val_df)} | Test: {len(test_df)}")

    # 2. Preprocessing (No Data Leakage)
    print("\n[2/6] Fitting preprocessor exclusively on training partition...")
    preprocessor.fit(train_df)
    prep_path = os.path.join(ARTIFACTS_DIR, "preprocessor.pkl")
    preprocessor.save(prep_path)

    X_train, y_train = preprocessor.transform(train_df)
    X_val, y_val = preprocessor.transform(val_df)
    X_test, y_test = preprocessor.transform(test_df)

    # 3. Train Random Forest
    print("\n[3/6] Training Random Forest ensemble classifier...")
    class_names = list(preprocessor.label_encoder.classes_)
    rf_classifier = RandomForestAttackClassifier(n_estimators=150, max_depth=12, random_state=42)
    rf_classifier.fit(X_train, y_train, classes=class_names)
    rf_path = os.path.join(ARTIFACTS_DIR, "random_forest.joblib")
    rf_classifier.save(rf_path)

    # 4. Train XGBoost
    print("\n[4/6] Training XGBoost multi-class gradient boosted trees...")
    xgb_classifier = XGBoostAttackClassifier(n_estimators=150, max_depth=6, learning_rate=0.08)
    xgb_classifier.fit(X_train, y_train, eval_set=[(X_val, y_val)], classes=class_names)
    xgb_path = os.path.join(ARTIFACTS_DIR, "xgboost.joblib")
    xgb_classifier.save(xgb_path)

    # 5. Train PyTorch LSTM
    print("\n[5/6] Training PyTorch Recurrent LSTM Sequence Detector...")
    lstm_detector = LSTMSequenceAttackDetector(input_dim=X_train.shape[1], hidden_dim=64, seq_length=4)
    lstm_detector.fit(X_train, y_train, epochs=15, batch_size=32, lr=0.004, classes=class_names)
    lstm_path = os.path.join(ARTIFACTS_DIR, "lstm.pt")
    lstm_detector.save(lstm_path)

    # 6. Evaluation on Holdout Test Set
    print("\n[6/6] Evaluating classifiers on unseen holdout test data:")
    print("-" * 65)

    rf_preds = rf_classifier.predict(X_test)
    xgb_preds = xgb_classifier.predict(X_test)

    # Convert y_test to string labels if predictions are string labels
    if len(rf_preds) > 0 and isinstance(rf_preds[0], (str, np.str_)):
        y_test_eval = preprocessor.inverse_transform_labels(y_test)
    else:
        y_test_eval = y_test

    # Evaluate RF and XGBoost
    for name, preds in [("Random Forest", rf_preds), ("XGBoost", xgb_preds)]:
        acc = accuracy_score(y_test_eval, preds)
        prec = precision_score(y_test_eval, preds, average="macro", zero_division=0)
        rec = recall_score(y_test_eval, preds, average="macro", zero_division=0)
        f1 = f1_score(y_test_eval, preds, average="macro", zero_division=0)
        print(f"{name:16s} | Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")

    # Evaluate LSTM on sequence test partition
    X_test_seq, y_test_seq = lstm_detector.create_sequences(X_test, y_test)
    lstm_preds, _, _ = lstm_detector.predict(X_test_seq)
    lstm_acc = accuracy_score(y_test_seq, lstm_preds)
    lstm_f1 = f1_score(y_test_seq, lstm_preds, average="macro", zero_division=0)
    print(f"{'PyTorch LSTM':16s} | Accuracy: {lstm_acc:.4f} | (Sequences evaluated: {len(y_test_seq)}) | F1: {lstm_f1:.4f}")
    print("-" * 65)

    # 7. Verify TreeSHAP Explainability
    print("\n[XAI Verification] Computing sample SHAP feature attribution on XGBoost prediction:")
    explainer = ModelExplainer(xgb_classifier)
    sample_feat = X_test[0]
    sample_pred_class = class_names.index(xgb_preds[0]) if xgb_preds[0] in class_names else int(xgb_preds[0])
    shap_res = explainer.explain_prediction(sample_feat, sample_pred_class, top_k=3)
    print(f"  Target: {shap_res['predicted_category']}")
    for factor in shap_res["contributing_factors"]:
        print(f"    - Rank {factor['rank']}: {factor['feature']} (Attribution: {factor['shap_attribution']:+.4f}) -> {factor['description']}")

    print("\nSupervised attack classification training successfully completed!")
    return {
        "random_forest_path": rf_path,
        "xgboost_path": xgb_path,
        "lstm_path": lstm_path,
    }


if __name__ == "__main__":
    train_and_evaluate_supervised()

