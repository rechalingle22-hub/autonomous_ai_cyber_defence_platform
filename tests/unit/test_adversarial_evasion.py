# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Adversarial Evasion & AI Robustness Testing Engine."""

import os
import sys
import numpy as np
import pandas as pd
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from ml.adversarial.evasion_evaluator import AdversarialEvasionEvaluator, adversarial_evaluator
from ml.features.definitions import NUMERICAL_FEATURES


def test_perturb_benign_mimicry_direction():
    """Verifies that benign mimicry shifts malicious features closer to benign baseline centroids."""
    evaluator = AdversarialEvasionEvaluator()
    np.random.seed(42)

    # Synthetic malicious samples (high packet count, high bytes)
    malicious_data = {
        feat: np.random.uniform(5000, 10000, 20) for feat in NUMERICAL_FEATURES
    }
    df_malicious = pd.DataFrame(malicious_data)

    perturbed_df = evaluator.perturb_benign_mimicry(df_malicious, epsilon=0.2)

    # Verify that perturbed samples shifted downwards toward benign centroids
    for feat in ["flow_duration", "tot_fwd_pkts", "tot_bwd_pkts"]:
        if feat in perturbed_df.columns and feat in evaluator.benign_baseline_means:
            orig_mean = df_malicious[feat].mean()
            pert_mean = perturbed_df[feat].mean()
            benign_mean = evaluator.benign_baseline_means[feat]
            # Since orig_mean > benign_mean, pert_mean should be shifted closer to benign_mean
            assert pert_mean < orig_mean, f"Feature {feat} was not shifted toward benign centroid"


def test_perturb_boundary_seeking_variance():
    """Verifies that decision boundary seeking perturbs key features using gradient noise."""
    evaluator = AdversarialEvasionEvaluator()
    np.random.seed(42)

    data = {feat: np.random.uniform(100, 500, 20) for feat in NUMERICAL_FEATURES}
    df = pd.DataFrame(data)

    perturbed = evaluator.perturb_boundary_seeking(df, epsilon=0.15)
    assert not perturbed.equals(df)
    assert perturbed.shape == df.shape


def test_apply_physical_bounds():
    """Ensures perturbed values never violate physical network constraints (negative ports/rates)."""
    evaluator = AdversarialEvasionEvaluator()
    df_unbounded = pd.DataFrame({
        "flow_duration": [-100.0, 50.0],
        "src_port": [-5, 70000],
        "dst_port": [0, 80],
        "port_entropy": [-1.0, 9.5],
        "flow_pkts_per_sec": [-10.0, 500.0],
    })

    bounded = evaluator.apply_physical_bounds(df_unbounded)

    assert bounded["flow_duration"].min() >= 0.0
    assert bounded["src_port"].iloc[0] == 1.0
    assert bounded["src_port"].iloc[1] == 65535.0
    assert bounded["dst_port"].iloc[0] == 1.0
    assert bounded["port_entropy"].iloc[0] == 0.0
    assert bounded["port_entropy"].iloc[1] == 8.0
    assert bounded["flow_pkts_per_sec"].min() >= 0.0


def test_ari_grading_thresholds():
    """Verifies letter grades assigned to Adversarial Robustness Index."""
    evaluator = AdversarialEvasionEvaluator()

    assert evaluator._grade_ari(0.95) == "A"
    assert evaluator._grade_ari(0.85) == "A"
    assert evaluator._grade_ari(0.84) == "B"
    assert evaluator._grade_ari(0.70) == "B"
    assert evaluator._grade_ari(0.69) == "C"
    assert evaluator._grade_ari(0.20) == "C"


def test_evaluate_models_adversarial_resilience():
    """Runs full adversarial evaluation across available models in ensemble."""
    evaluator = AdversarialEvasionEvaluator()
    res = evaluator.evaluate_models(epsilon=0.15, technique="BENIGN_MIMICRY", test_sample_size=30)

    assert "models" in res
    assert "ensemble_adversarial_robustness_index" in res
    assert "ensemble_robustness_grade" in res
    assert res["total_attack_samples_tested"] == 30
    assert res["perturbation_epsilon"] == 0.15
    assert res["technique_applied"] == "BENIGN_MIMICRY"
    assert res["ensemble_robustness_grade"] in ("A", "B", "C")
    assert 0.0 <= res["ensemble_adversarial_robustness_index"] <= 1.0

    # Ensure individual model evaluations are present
    for m_name, m_bench in res["models"].items():
        assert "clean_accuracy" in m_bench
        assert "adversarial_accuracy" in m_bench
        assert "evasion_success_rate" in m_bench
        assert "adversarial_robustness_index" in m_bench
        assert m_bench["robustness_grade"] in ("A", "B", "C")

