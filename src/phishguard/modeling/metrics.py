"""Threshold selection and binary-classification metrics."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def choose_threshold(
    labels: NDArray[np.int_], probabilities: NDArray[np.float64]
) -> tuple[float, float]:
    """Choose the validation threshold with best F1, then recall, then proximity to 0.5."""

    best_threshold = 0.5
    best_f1 = -1.0
    best_rank = (-1.0, -1.0, -1.0)
    for threshold in np.linspace(0.05, 0.95, 91):
        predictions = (probabilities >= threshold).astype(np.int_)
        score = float(f1_score(labels, predictions, zero_division=0))
        recall = float(recall_score(labels, predictions, zero_division=0))
        rank = (score, recall, -abs(float(threshold) - 0.5))
        if rank > best_rank:
            best_rank = rank
            best_threshold = float(threshold)
            best_f1 = score
    return best_threshold, best_f1


def binary_metrics(
    labels: NDArray[np.int_],
    probabilities: NDArray[np.float64],
    threshold: float,
) -> dict[str, object]:
    """Calculate operational and ranking metrics for the phishing class."""

    predictions = (probabilities >= threshold).astype(np.int_)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    negative_count = tn + fp
    return {
        "threshold": round(threshold, 4),
        "samples": int(labels.size),
        "accuracy": round(float(accuracy_score(labels, predictions)), 6),
        "precision": round(float(precision_score(labels, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(labels, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(labels, predictions, zero_division=0)), 6),
        "pr_auc": round(float(average_precision_score(labels, probabilities)), 6),
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6),
        "brier_score": round(float(brier_score_loss(labels, probabilities)), 6),
        "false_positive_rate": round(float(fp / negative_count), 6) if negative_count else 0.0,
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "predicted_phishing": int(predictions.sum()),
    }
