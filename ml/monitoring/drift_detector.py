# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Statistical Data & Concept Drift Detection Engine.

Implements:
1. Population Stability Index (PSI) with adaptive percentile binning
2. Two-Sample Kolmogorov-Smirnov (KS) test for continuous distribution divergence
3. Per-feature and dataset-level drift aggregation across the 14-dimensional telemetry space
"""

import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import numpy as np  # type: ignore
import pandas as pd  # type: ignore
from scipy import stats  # type: ignore

try:
    from ml.features.definitions import NUMERICAL_FEATURES  # type: ignore
except ImportError:
    from ..features.definitions import NUMERICAL_FEATURES  # type: ignore


class DataDriftDetector:
    """Calculates statistical drift between baseline training telemetry and current operational windows."""

    def __init__(
        self,
        psi_warning_threshold: float = 0.10,
        psi_critical_threshold: float = 0.25,
        ks_alpha: float = 0.01,
        num_bins: int = 10,
    ) -> None:
        self.psi_warning_threshold = psi_warning_threshold
        self.psi_critical_threshold = psi_critical_threshold
        self.ks_alpha = ks_alpha
        self.num_bins = num_bins

    def calculate_psi(
        self,
        expected: np.ndarray,
        actual: np.ndarray,
        num_bins: Optional[int] = None,
        epsilon: float = 1e-4,
    ) -> float:
        exp_clean = np.asarray(expected, dtype=float)
        act_clean = np.asarray(actual, dtype=float)

        # Drop NaNs and infinite values
        exp_clean = exp_clean[np.isfinite(exp_clean)]
        act_clean = act_clean[np.isfinite(act_clean)]

        if len(exp_clean) == 0 or len(act_clean) == 0:
            return 0.0

        # Adaptive bins based on sample size to prevent small-sample bin starvation
        k = num_bins or (5 if min(len(exp_clean), len(act_clean)) < 400 else self.num_bins)

        # If data is virtually constant
        if np.isclose(np.min(exp_clean), np.max(exp_clean)):
            if np.isclose(np.min(act_clean), np.max(act_clean)) and np.isclose(exp_clean[0], act_clean[0]):
                return 0.0
            return 1.0

        # Percentile-based bins on expected baseline
        percentiles = np.linspace(0, 100, k + 1)
        bin_edges = np.percentile(exp_clean, percentiles)
        bin_edges = np.unique(bin_edges)

        # Fallback to linear bins if duplicate percentiles collapsed bins
        if len(bin_edges) < 3:
            bin_edges = np.linspace(np.min(exp_clean), np.max(exp_clean), k + 1)

        # Ensure edges cover actual values
        bin_edges[0] = min(bin_edges[0], np.min(act_clean)) - 1e-5
        bin_edges[-1] = max(bin_edges[-1], np.max(act_clean)) + 1e-5

        exp_counts, _ = np.histogram(exp_clean, bins=bin_edges)
        act_counts, _ = np.histogram(act_clean, bins=bin_edges)

        # Proportions with epsilon smoothing
        exp_pct = exp_counts / len(exp_clean)
        act_pct = act_counts / len(act_clean)

        exp_pct = np.where(exp_pct == 0, epsilon, exp_pct)
        act_pct = np.where(act_pct == 0, epsilon, act_pct)

        # Re-normalize
        exp_pct = exp_pct / np.sum(exp_pct)
        act_pct = act_pct / np.sum(act_pct)

        # PSI formula: sum((A - E) * ln(A / E))
        psi_val = np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct))
        return float(max(0.0, psi_val))

    def calculate_ks_test(
        self,
        reference: np.ndarray,
        current: np.ndarray,
    ) -> Tuple[float, float]:
        """Performs two-sample Kolmogorov-Smirnov test returning (statistic, p_value)."""
        ref_clean = np.asarray(reference, dtype=float)
        cur_clean = np.asarray(current, dtype=float)

        ref_clean = ref_clean[np.isfinite(ref_clean)]
        cur_clean = cur_clean[np.isfinite(cur_clean)]

        if len(ref_clean) == 0 or len(cur_clean) == 0:
            return 0.0, 1.0

        res = stats.ks_2samp(ref_clean, cur_clean)
        return float(res.statistic), float(res.pvalue)

    def evaluate_feature_drift(
        self,
        baseline_df: pd.DataFrame,
        current_df: pd.DataFrame,
        features: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Calculates drift statistics for each individual telemetry feature."""
        target_features = features or [f for f in NUMERICAL_FEATURES if f in baseline_df.columns and f in current_df.columns]
        results = {}

        for feat in target_features:
            base_vals = baseline_df[feat].dropna().values
            curr_vals = current_df[feat].dropna().values

            if len(base_vals) == 0 or len(curr_vals) == 0:
                continue

            psi = self.calculate_psi(base_vals, curr_vals)
            ks_stat, ks_pvalue = self.calculate_ks_test(base_vals, curr_vals)

            base_mean = float(np.mean(base_vals))
            curr_mean = float(np.mean(curr_vals))
            base_std = float(np.std(base_vals))
            curr_std = float(np.std(curr_vals))

            # Drift Classification: require PSI >= warning threshold or (ks divergence with non-trivial PSI >= 0.05)
            if psi >= self.psi_critical_threshold or (ks_pvalue < self.ks_alpha and psi >= self.psi_warning_threshold):
                drift_detected = True
                status = "CRITICAL"
            elif psi >= self.psi_warning_threshold or (ks_pvalue < self.ks_alpha and psi >= 0.05):
                drift_detected = True
                status = "WARNING"
            else:
                drift_detected = False
                status = "STABLE"

            results[feat] = {
                "feature": feat,
                "psi": round(psi, 4),
                "ks_statistic": round(ks_stat, 4),
                "ks_pvalue": round(ks_pvalue, 6),
                "baseline_mean": round(base_mean, 3),
                "current_mean": round(curr_mean, 3),
                "baseline_std": round(base_std, 3),
                "current_std": round(curr_std, 3),
                "drift_detected": drift_detected,
                "status": status,
            }

        return results

    def evaluate_dataset_drift(
        self,
        baseline_df: pd.DataFrame,
        current_df: pd.DataFrame,
        features: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Calculates global dataset drift across all telemetry dimensions."""
        feature_results = self.evaluate_feature_drift(baseline_df, current_df, features)
        
        if not feature_results:
            return {
                "drift_detected": False,
                "status": "STABLE",
                "mean_psi": 0.0,
                "max_psi": 0.0,
                "drifted_features_count": 0,
                "total_features_evaluated": 0,
                "drifted_features": [],
                "feature_metrics": {},
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
            }

        psis = [m["psi"] for m in feature_results.values()]
        drifted = [f for f, m in feature_results.items() if m["drift_detected"]]
        critical = [f for f, m in feature_results.items() if m["status"] == "CRITICAL"]

        mean_psi = float(np.mean(psis))
        max_psi = float(np.max(psis))

        if len(critical) >= 2 or max_psi >= self.psi_critical_threshold or mean_psi >= self.psi_critical_threshold:
            overall_status = "CRITICAL"
            drift_detected = True
        elif len(drifted) >= 2 or max_psi >= self.psi_warning_threshold or mean_psi >= self.psi_warning_threshold:
            overall_status = "WARNING"
            drift_detected = True
        else:
            overall_status = "STABLE"
            drift_detected = False

        return {
            "drift_detected": drift_detected,
            "status": overall_status,
            "mean_psi": round(mean_psi, 4),
            "max_psi": round(max_psi, 4),
            "drifted_features_count": len(drifted),
            "total_features_evaluated": len(feature_results),
            "drifted_features": drifted,
            "feature_metrics": feature_results,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }


# Global default detector instance
drift_detector = DataDriftDetector()
