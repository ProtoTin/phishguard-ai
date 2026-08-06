"""Offline ML features and deterministic rule-based comparators."""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Sequence
from typing import Protocol, Self, cast
from urllib.parse import urlsplit

import numpy as np
from numpy.typing import NDArray
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.pipeline import FeatureUnion, Pipeline

SUSPICIOUS_TOKENS = {
    "account",
    "auth",
    "bank",
    "billing",
    "confirm",
    "credential",
    "login",
    "password",
    "payment",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}


class BinaryProbabilisticModel(Protocol):
    """Small interface shared by the scikit-learn baseline pipelines."""

    def fit(self, texts: Sequence[str], labels: NDArray[np.int_]) -> BinaryProbabilisticModel: ...

    def predict_proba(self, texts: Sequence[str]) -> NDArray[np.float64]: ...


def _safe_url_parts(value: str) -> tuple[str, str, str, str]:
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate if "://" in candidate else f"http://{candidate}")
        hostname = (parsed.hostname or "").casefold()
        return hostname, parsed.path, parsed.query, parsed.scheme.casefold()
    except ValueError:
        return "", candidate, "", ""


def url_lexical_vector(value: str) -> list[float]:
    """Extract bounded URL-only features without network access."""

    hostname, path, query, scheme = _safe_url_parts(value)
    lowered = value.casefold()
    labels = [part for part in hostname.split(".") if part]
    try:
        is_ip = float(bool(hostname) and bool(ipaddress.ip_address(hostname)))
    except ValueError:
        is_ip = 0.0
    suspicious_count = sum(token in lowered for token in SUSPICIOUS_TOKENS)
    entropy = 0.0
    if lowered:
        frequencies = {
            character: lowered.count(character) / len(lowered) for character in set(lowered)
        }
        entropy = -sum(probability * math.log2(probability) for probability in frequencies.values())
    return [
        min(len(value), 500) / 500,
        min(len(hostname), 200) / 200,
        min(len(path), 300) / 300,
        min(len(query), 300) / 300,
        min(len(labels), 10) / 10,
        min(value.count("."), 10) / 10,
        min(value.count("-"), 20) / 20,
        min(sum(character.isdigit() for character in value), 50) / 50,
        float("@" in value),
        float("xn--" in hostname),
        is_ip,
        float(scheme == "https"),
        min(suspicious_count, 6) / 6,
        min(entropy, 8) / 8,
    ]


class URLLexicalFeatures(BaseEstimator, TransformerMixin):  # type: ignore[misc]
    """Scikit-learn transformer for URL-only numeric features."""

    def fit(self, values: Sequence[str], labels: object = None) -> Self:
        return self

    def transform(self, values: Sequence[str]) -> csr_matrix:
        matrix = np.asarray([url_lexical_vector(value) for value in values], dtype=np.float32)
        return csr_matrix(matrix)

    def get_feature_names_out(self, input_features: object = None) -> NDArray[np.str_]:
        return np.asarray(
            [
                "url_length",
                "hostname_length",
                "path_length",
                "query_length",
                "hostname_labels",
                "dots",
                "hyphens",
                "digits",
                "has_at",
                "has_punycode",
                "host_is_ip",
                "uses_https",
                "suspicious_tokens",
                "character_entropy",
            ],
            dtype=np.str_,
        )


def build_email_model(seed: int = 20260806) -> BinaryProbabilisticModel:
    """Create a word-and-character TF-IDF logistic-regression pipeline."""

    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=2,
                    max_df=0.995,
                    max_features=50_000,
                    sublinear_tf=True,
                    strip_accents="unicode",
                    dtype=np.float32,
                ),
            ),
            (
                "character",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=50_000,
                    sublinear_tf=True,
                    dtype=np.float32,
                ),
            ),
        ]
    )
    pipeline = Pipeline(
        [
            ("features", features),
            (
                "classifier",
                LogisticRegression(
                    C=2.0,
                    class_weight="balanced",
                    max_iter=1_000,
                    random_state=seed,
                    solver="liblinear",
                ),
            ),
        ]
    )
    return cast(BinaryProbabilisticModel, pipeline)


def build_url_model(seed: int = 20260806) -> BinaryProbabilisticModel:
    """Create a character TF-IDF plus lexical-feature URL pipeline."""

    features = FeatureUnion(
        [
            (
                "character",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=3,
                    max_features=75_000,
                    sublinear_tf=True,
                    dtype=np.float32,
                ),
            ),
            ("lexical", URLLexicalFeatures()),
        ]
    )
    pipeline = Pipeline(
        [
            ("features", features),
            (
                "classifier",
                SGDClassifier(
                    loss="log_loss",
                    alpha=0.00001,
                    average=True,
                    class_weight="balanced",
                    max_iter=1_000,
                    random_state=seed,
                    tol=0.0001,
                ),
            ),
        ]
    )
    return cast(BinaryProbabilisticModel, pipeline)


def email_rule_score(text: str) -> float:
    """Return a deliberately simple comparator score for email text."""

    lowered = text.casefold()
    patterns = [
        r"\b(urgent|immediately|within 24 hours|final warning)\b",
        r"\b(password|credential|login|sign[ -]?in)\b",
        r"\b(verify|confirm|validate|update)\b.{0,35}\b(account|identity|payment)\b",
        r"\b(gift card|wire transfer|crypto|bitcoin|bank details)\b",
        r"\b(click here|open the link|download the attachment)\b",
        r"\b(winner|won|prize|inheritance|beneficiary)\b",
        r"<form\b|javascript:|onerror\s*=",
    ]
    matches = sum(bool(re.search(pattern, lowered)) for pattern in patterns)
    link_bonus = 1 if lowered.count("http://") + lowered.count("https://") >= 2 else 0
    return min(0.95, 0.05 + 0.18 * matches + 0.12 * link_bonus)


def url_rule_score(value: str) -> float:
    """Return a deliberately simple comparator score for a URL string."""

    hostname, _, _, scheme = _safe_url_parts(value)
    lowered = value.casefold()
    signals = 0
    signals += len(value) > 100
    signals += len([label for label in hostname.split(".") if label]) > 4
    signals += "@" in value
    signals += "xn--" in hostname
    signals += scheme != "https"
    signals += sum(token in lowered for token in SUSPICIOUS_TOKENS) >= 2
    try:
        signals += bool(hostname) and bool(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    return min(0.95, 0.05 + 0.16 * signals)


def rule_probabilities(content_type: str, texts: Sequence[str]) -> NDArray[np.float64]:
    """Score a batch with the fixed rule comparator."""

    scorer = email_rule_score if content_type == "email" else url_rule_score
    return np.asarray([scorer(text) for text in texts], dtype=np.float64)
