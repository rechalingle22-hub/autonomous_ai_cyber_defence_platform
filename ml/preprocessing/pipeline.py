"""Leakage-free ML Preprocessing Pipeline for Cybersecurity Telemetry.

Guarantees:
- Strict train/val/test splitting BEFORE fitting.
- Fitted statistics (medians, scalers, encoders) computed exclusively on training split.
- Robust handling of infinite, NaN, and high-outlier flow features.
- Reusable serialization for online low-latency inference.
"""

import os
import pickle
from typing import Tuple, List, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from ml.features.definitions import NUMERICAL_FEATURES, ATTACK_CATEGORIES, FEATURE_DEFAULTS


class CybersecurityPreprocessor:
    """Production preprocessing pipeline for intrusion detection & anomaly models."""

    def __init__(
        self,
        feature_columns: Optional[List[str]] = None,
        target_column: str = "attack_category",
    ) -> None:
        self.feature_columns = feature_columns or NUMERICAL_FEATURES.copy()
        self.target_column = target_column
        self.scaler = RobustScaler()
        self.label_encoder = LabelEncoder()
        self.impute_medians: Dict[str, float] = {}
        self.is_fitted: bool = False

        # Pre-seed label encoder with official categories to maintain stable class indices
        self.label_encoder.fit(ATTACK_CATEGORIES)

    def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Cleans infinite values, missing columns, and derives missing flow statistics."""
        clean_df = df.copy()

        # Ensure all expected feature columns exist, filling with default values if absent
        for col in self.feature_columns:
            if col not in clean_df.columns:
                clean_df[col] = FEATURE_DEFAULTS.get(col, 0.0)

        # Compute derived flow ratios if zero or missing
        fwd_pkts = clean_df["total_fwd_packets"].clip(lower=1.0)
        bwd_pkts = clean_df["total_bwd_packets"].clip(lower=1.0)
        tot_pkts = (clean_df["total_fwd_packets"] + clean_df["total_bwd_packets"]).clip(lower=1.0)
        dur_s = (clean_df["flow_duration_ms"] / 1000.0).clip(lower=0.001)

        if "fwd_packet_length_mean" in clean_df.columns:
            clean_df["fwd_packet_length_mean"] = clean_df["fwd_packet_length_mean"].replace(0.0, np.nan).fillna(
                clean_df["total_fwd_bytes"] / fwd_pkts
            )
        if "bwd_packet_length_mean" in clean_df.columns:
            clean_df["bwd_packet_length_mean"] = clean_df["bwd_packet_length_mean"].replace(0.0, np.nan).fillna(
                clean_df["total_bwd_bytes"] / bwd_pkts
            )
        if "flow_bytes_per_sec" in clean_df.columns:
            clean_df["flow_bytes_per_sec"] = clean_df["flow_bytes_per_sec"].replace(0.0, np.nan).fillna(
                (clean_df["total_fwd_bytes"] + clean_df["total_bwd_bytes"]) / dur_s
            )
        if "flow_packets_per_sec" in clean_df.columns:
            clean_df["flow_packets_per_sec"] = clean_df["flow_packets_per_sec"].replace(0.0, np.nan).fillna(
                tot_pkts / dur_s
            )
        if "flow_iat_mean" in clean_df.columns:
            clean_df["flow_iat_mean"] = clean_df["flow_iat_mean"].replace(0.0, np.nan).fillna(
                clean_df["flow_duration_ms"] / tot_pkts
            )

        # Replace infinite values with NaN for imputation
        clean_df[self.feature_columns] = clean_df[self.feature_columns].replace([np.inf, -np.inf], np.nan)

        return clean_df

    def split_data(
        self,
        df: pd.DataFrame,
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Performs stratified train/val/test splitting before any featurization or fitting."""
        stratify = df[self.target_column] if self.target_column in df.columns else None

        # Step 1: Split into Train+Val and Test
        train_val_df, test_df = train_test_split(
            df,
            test_size=test_size,
            random_state=random_state,
            stratify=stratify,
        )

        # Step 2: Split Train+Val into Train and Validation
        val_ratio = val_size / (1.0 - test_size)
        stratify_val = train_val_df[self.target_column] if self.target_column in train_val_df.columns else None

        train_df, val_df = train_test_split(
            train_val_df,
            test_size=val_ratio,
            random_state=random_state,
            stratify=stratify_val,
        )

        return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)

    def fit(self, train_df: pd.DataFrame) -> "CybersecurityPreprocessor":
        """Fits imputer medians and robust scaler strictly on the training partition."""
        cleaned = self.clean_dataframe(train_df)
        X = cleaned[self.feature_columns]

        # 1. Calculate and store median values on training set only
        for col in self.feature_columns:
            median_val = X[col].median()
            self.impute_medians[col] = float(median_val) if pd.notnull(median_val) else FEATURE_DEFAULTS.get(col, 0.0)

        # 2. Impute training set
        X_imputed = X.fillna(self.impute_medians)

        # 3. Fit scaler
        self.scaler.fit(X_imputed)

        # 4. Fit label encoder on observed training classes
        if self.target_column in cleaned.columns:
            unique_classes = sorted(list(cleaned[self.target_column].unique()))
            if "BENIGN" in unique_classes:
                unique_classes.remove("BENIGN")
                unique_classes = ["BENIGN"] + unique_classes
            self.label_encoder.fit(unique_classes)

        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Transforms feature vectors using fitted training statistics."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before calling transform()")

        cleaned = self.clean_dataframe(df)
        X = cleaned[self.feature_columns]

        # 1. Impute using saved training medians (never calculate medians on test/live data)
        X_imputed = X.fillna(self.impute_medians)

        # 2. Scale features
        X_scaled = self.scaler.transform(X_imputed)

        # 3. Encode labels if present
        y_encoded = None
        if self.target_column in cleaned.columns:
            known_classes = set(self.label_encoder.classes_)
            default_fallback = "BENIGN" if "BENIGN" in known_classes else list(known_classes)[0]
            labels = cleaned[self.target_column].apply(
                lambda x: x if x in known_classes else default_fallback
            )
            y_encoded = self.label_encoder.transform(labels)

        return X_scaled, y_encoded

    def fit_transform(self, train_df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Fits on training set and returns transformed features and labels."""
        return self.fit(train_df).transform(train_df)

    def inverse_transform_labels(self, y_indices: np.ndarray) -> List[str]:
        """Converts numeric prediction indices back to human-readable attack category names."""
        return list(self.label_encoder.inverse_transform(y_indices))

    def save(self, filepath: str) -> None:
        """Serializes fitted preprocessor artifacts to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, filepath: str) -> "CybersecurityPreprocessor":
        """Loads a serialized preprocessor from disk."""
        with open(filepath, "rb") as f:
            return pickle.load(f)

