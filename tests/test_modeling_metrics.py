"""Tests for threshold selection and security-relevant metrics."""

import numpy as np

from phishguard.modeling.metrics import binary_metrics, choose_threshold


def test_threshold_and_metrics_for_separable_predictions() -> None:
    labels = np.asarray([0, 0, 1, 1], dtype=np.int_)
    probabilities = np.asarray([0.1, 0.2, 0.8, 0.9], dtype=np.float64)

    threshold, score = choose_threshold(labels, probabilities)
    metrics = binary_metrics(labels, probabilities, threshold)

    assert score == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["confusion_matrix"] == {
        "true_negative": 2,
        "false_positive": 0,
        "false_negative": 0,
        "true_positive": 2,
    }


def test_metrics_handles_all_positive_predictions() -> None:
    labels = np.asarray([0, 1], dtype=np.int_)
    probabilities = np.asarray([0.9, 0.9], dtype=np.float64)

    metrics = binary_metrics(labels, probabilities, 0.5)

    assert metrics["predicted_phishing"] == 2
    assert metrics["false_positive_rate"] == 1.0
