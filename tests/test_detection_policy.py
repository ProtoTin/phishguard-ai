"""Tests for calibrated risk-score policy bands."""

import pytest

from phishguard.detection.policy import (
    POLICY_VERSION,
    decide,
    decide_unverified,
    policy_document,
    risk_score,
)


@pytest.mark.parametrize(
    ("probability", "score", "classification", "action"),
    [
        (-1.0, 0, "legitimate", "allow"),
        (0.294, 29, "legitimate", "allow"),
        (0.30, 30, "suspicious", "warn"),
        (0.599, 60, "phishing", "quarantine"),
        (0.849, 85, "phishing", "block"),
        (2.0, 100, "phishing", "block"),
    ],
)
def test_policy_boundaries(
    probability: float, score: int, classification: str, action: str
) -> None:
    decision = decide(probability)

    assert risk_score(probability) == score
    assert decision.risk_score == score
    assert decision.classification == classification
    assert decision.recommended_action == action
    assert decision.policy_version == POLICY_VERSION


def test_policy_document_is_advisory_and_complete() -> None:
    document = policy_document()

    assert document["advisory_only"] is True
    assert document["policy_version"] == POLICY_VERSION
    bands = document["bands"]
    assert isinstance(bands, list)
    assert bands[0]["minimum"] == 0
    assert bands[-1]["maximum"] == 100


@pytest.mark.parametrize(("probability", "score"), [(0.01, 30), (0.45, 45), (0.99, 59)])
def test_unverified_decision_bounds_model_only_scores(probability: float, score: int) -> None:
    decision = decide_unverified(probability)

    assert decision.risk_score == score
    assert decision.classification == "unverified"
    assert decision.recommended_action == "warn"
