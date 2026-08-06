"""Tests for ML feature pipelines and fixed rule comparators."""

import numpy as np

from phishguard.modeling.baselines import (
    URLLexicalFeatures,
    build_email_model,
    build_url_model,
    email_rule_score,
    rule_probabilities,
    url_lexical_vector,
    url_rule_score,
)


def test_url_lexical_features_detect_offline_signals() -> None:
    safe = url_lexical_vector("https://example.com/about")
    risky = url_lexical_vector("http://192.0.2.10/login/verify-account?password=reset")

    assert len(safe) == len(risky) == 14
    assert risky[10] == 1.0
    assert risky[12] > safe[12]
    matrix = (
        URLLexicalFeatures()
        .fit(["https://example.com"])
        .transform(["https://example.com", "http://bad.test/login"])
    )
    assert matrix.shape == (2, 14)
    assert len(URLLexicalFeatures().get_feature_names_out()) == 14


def test_rule_baselines_score_obvious_lures_higher() -> None:
    safe_email = "The weekly project meeting starts Tuesday at ten."
    risky_email = "Urgent: click here immediately to verify your account password."
    safe_url = "https://example.com/about"
    risky_url = "http://192.0.2.2/login/verify/password"

    assert email_rule_score(risky_email) > email_rule_score(safe_email)
    assert url_rule_score(risky_url) > url_rule_score(safe_url)
    assert rule_probabilities("email", [safe_email, risky_email]).shape == (2,)
    assert rule_probabilities("url", [safe_url, risky_url]).shape == (2,)


def test_email_pipeline_fits_and_predicts_probabilities() -> None:
    texts = [
        "team meeting project update",
        "team lunch project notes",
        "meeting notes and agenda",
        "urgent verify password account",
        "verify your account login",
        "urgent password reset login",
    ]
    labels = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.int_)
    model = build_email_model(seed=7).fit(texts, labels)

    probabilities = model.predict_proba(["project meeting", "urgent verify login"])

    assert probabilities.shape == (2, 2)
    assert np.allclose(probabilities.sum(axis=1), 1.0)


def test_url_pipeline_fits_and_predicts_probabilities() -> None:
    texts = [
        "https://example.com/about",
        "https://example.com/contact",
        "https://docs.example.org/start",
        "https://docs.example.org/guide",
        "http://bad.test/login/verify",
        "http://bad.test/login/password",
        "http://evil.test/account/verify",
        "http://evil.test/account/password",
    ]
    labels = np.asarray([0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int_)
    model = build_url_model(seed=7).fit(texts, labels)

    probabilities = model.predict_proba(
        ["https://example.com/help", "http://bad.test/login/account"]
    )

    assert probabilities.shape == (2, 2)
    assert np.allclose(probabilities.sum(axis=1), 1.0)
