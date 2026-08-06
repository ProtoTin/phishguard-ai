"""Tests for deterministic evidence and linear feature contributions."""

from collections.abc import Sequence

import numpy as np
from numpy.typing import NDArray

from phishguard.detection.explanations import (
    email_evidence,
    explain,
    feature_contributions,
    url_evidence,
)
from phishguard.modeling.baselines import BinaryProbabilisticModel, build_email_model


class FixedCalibratedModel:
    def __init__(self, probability: float) -> None:
        self.probability = probability

    def predict_proba(self, texts: Sequence[str]) -> NDArray[np.float64]:
        positive = np.full(len(texts), self.probability, dtype=np.float64)
        return np.column_stack((1 - positive, positive))


def fitted_email_model() -> BinaryProbabilisticModel:
    texts = [
        "team meeting project update",
        "team lunch project notes",
        "meeting notes and agenda",
        "urgent verify password account",
        "verify your account login",
        "urgent password reset login",
    ]
    labels = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.int_)
    return build_email_model(seed=7).fit(texts, labels)


def test_evidence_uses_controlled_descriptions() -> None:
    email = email_evidence(
        "Urgent: click here immediately to verify your account password. "
        "https://one.test https://two.test"
    )
    url = url_evidence("http://192.0.2.1/login/verify/password")

    assert {item.code for item in email} >= {
        "urgent_language",
        "credential_request",
        "account_verification",
        "link_prompt",
        "multiple_links",
    }
    assert {item.code for item in url} >= {
        "ip_hostname",
        "no_https",
        "suspicious_terms",
    }


def test_linear_contributions_and_complete_explanation() -> None:
    model = fitted_email_model()
    text = "Urgent: verify your account login password immediately."

    supporting, mitigating = feature_contributions(model, text, limit=3)
    result = explain("email", text, model, FixedCalibratedModel(0.91))

    assert supporting
    assert len({item.feature for item in supporting}) == len(supporting)
    assert len(supporting) <= 3
    assert len(mitigating) <= 3
    assert result["risk_score"] == 91
    assert result["classification"] == "phishing"
    assert result["recommended_action"] == "block"
    assert result["advisory_only"] is True
    assert result["reasons"]


def test_explanation_falls_back_when_no_rule_evidence() -> None:
    model = fitted_email_model()

    result = explain(
        "email",
        "An unfamiliar neutral sentence.",
        model,
        FixedCalibratedModel(0.2),
    )

    assert result["classification"] == "legitimate"
    assert result["reasons"]
