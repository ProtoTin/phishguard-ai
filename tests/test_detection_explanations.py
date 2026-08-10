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
from phishguard.detection.reputation import TRANCO_TOP_DOMAINS, reputable_https_host
from phishguard.modeling.baselines import (
    BinaryProbabilisticModel,
    build_email_model,
    build_url_model,
)


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


def fitted_url_model() -> BinaryProbabilisticModel:
    texts = [
        "https://example.com/docs/about",
        "https://example.org/docs/contact",
        "https://docs.example.org/docs/guide",
        "http://bad.test/login/verify",
        "http://bad.test/login/password",
        "http://evil.test/account/verify",
    ]
    labels = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.int_)
    return build_url_model(seed=7).fit(texts, labels)


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


def test_known_https_host_caps_false_positive_but_not_lookalike() -> None:
    model = fitted_url_model()

    linkedin = explain("url", "https://linkedin.com/feed/", model, FixedCalibratedModel(0.99))
    lookalike = explain(
        "url",
        "https://evil.test/redirect/linkedin.com/login/verify",
        model,
        FixedCalibratedModel(0.99),
    )

    assert linkedin["risk_score"] == 20
    assert linkedin["classification"] == "legitimate"
    linkedin_evidence = linkedin["evidence"]
    assert isinstance(linkedin_evidence, list)
    assert "popular_domain" in {item["code"] for item in linkedin_evidence}
    assert lookalike["risk_score"] == 99
    assert lookalike["classification"] == "phishing"


def test_known_host_match_is_exact_and_https_only() -> None:
    assert reputable_https_host("https://www.linkedin.com/feed/") == "linkedin.com"
    assert reputable_https_host("http://linkedin.com/feed/") is None
    assert reputable_https_host("https://login.linkedin.com/") is None
    assert reputable_https_host("https://linkedin.com.evil.test/") is None
    assert reputable_https_host("https://[invalid") is None


def test_bare_youtube_domain_is_normalized_and_reputation_mitigated() -> None:
    model = fitted_url_model()

    result = explain("url", "youtube.com", model, FixedCalibratedModel(0.99))

    evidence = result["evidence"]
    assert isinstance(evidence, list)
    assert result["risk_score"] == 20
    assert result["classification"] == "legitimate"
    assert {item["code"] for item in evidence} >= {"assumed_https", "popular_domain"}
    assert TRANCO_TOP_DOMAINS["youtube.com"] == 8
    assert TRANCO_TOP_DOMAINS["youtu.be"] == 47
    assert len(TRANCO_TOP_DOMAINS) == 1_000


def test_unknown_domain_without_concrete_evidence_is_unverified() -> None:
    model = fitted_url_model()

    result = explain("url", "https://new-business.example/about", model, FixedCalibratedModel(0.99))

    evidence = result["evidence"]
    assert isinstance(evidence, list)
    assert result["risk_score"] == 59
    assert result["classification"] == "unverified"
    assert result["recommended_action"] == "warn"
    assert "unverified_domain" in {item["code"] for item in evidence}


def test_concrete_phishing_evidence_overrides_popular_domain_mitigation() -> None:
    model = fitted_url_model()

    result = explain(
        "url",
        "https://youtube.com/login/verify/password",
        model,
        FixedCalibratedModel(0.99),
    )

    evidence = result["evidence"]
    assert isinstance(evidence, list)
    assert result["risk_score"] == 99
    assert result["classification"] == "phishing"
    assert "suspicious_terms" in {item["code"] for item in evidence}
    assert "popular_domain" not in {item["code"] for item in evidence}
