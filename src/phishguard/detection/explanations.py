"""Human-readable evidence and linear-model feature contributions."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Protocol, cast
from urllib.parse import urlsplit

import numpy as np
from numpy.typing import NDArray

from phishguard import __version__
from phishguard.detection.policy import decide
from phishguard.modeling.baselines import BinaryProbabilisticModel


@dataclass(frozen=True)
class Evidence:
    """Deterministic evidence found directly in submitted content."""

    code: str
    description: str


@dataclass(frozen=True)
class FeatureContribution:
    """One active linear-model feature and its signed contribution."""

    feature: str
    contribution: float


class CalibratedModel(Protocol):
    def predict_proba(self, texts: Sequence[str]) -> NDArray[np.float64]: ...


class FeaturesTransformer(Protocol):
    def transform(self, texts: Sequence[str]) -> object: ...

    def get_feature_names_out(self) -> NDArray[np.str_]: ...


class SparseFeatureRow(Protocol):
    data: NDArray[np.float64]
    indices: NDArray[np.int_]


class SparseFeatureMatrix(Protocol):
    def getrow(self, index: int) -> SparseFeatureRow: ...


EMAIL_EVIDENCE_PATTERNS = (
    (
        "urgent_language",
        re.compile(r"\b(urgent|immediately|final warning|within 24 hours)\b", re.I),
        "Uses urgent or time-pressure language.",
    ),
    (
        "credential_request",
        re.compile(r"\b(password|credential|login|sign[ -]?in)\b", re.I),
        "Mentions credentials, passwords, or signing in.",
    ),
    (
        "account_verification",
        re.compile(r"\b(verify|confirm|validate|update)\b.{0,40}\b(account|identity)\b", re.I),
        "Requests account or identity verification.",
    ),
    (
        "payment_request",
        re.compile(r"\b(gift card|wire transfer|crypto|bitcoin|bank details)\b", re.I),
        "Requests a high-risk payment method or banking details.",
    ),
    (
        "link_prompt",
        re.compile(r"\b(click here|open the link|follow this link)\b", re.I),
        "Prompts the recipient to follow a link.",
    ),
    (
        "prize_or_inheritance",
        re.compile(r"\b(winner|won|prize|inheritance|beneficiary)\b", re.I),
        "Uses prize, inheritance, or beneficiary language.",
    ),
    (
        "embedded_form_or_script",
        re.compile(r"<form\b|javascript:|onerror\s*=", re.I),
        "Contains an embedded form or script-like HTML pattern.",
    ),
)


def email_evidence(text: str) -> list[Evidence]:
    """Find controlled-template warning signs in email text."""

    evidence = [
        Evidence(code, description)
        for code, pattern, description in EMAIL_EVIDENCE_PATTERNS
        if pattern.search(text)
    ]
    link_count = len(re.findall(r"https?://", text, flags=re.I))
    if link_count >= 2:
        evidence.append(Evidence("multiple_links", "Contains multiple web links."))
    return evidence


def _url_parts(value: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(value if "://" in value else f"http://{value}")
        return (parsed.hostname or "").casefold(), parsed.scheme.casefold()
    except ValueError:
        return "", ""


def url_evidence(value: str) -> list[Evidence]:
    """Find URL warning signs without resolving or visiting the destination."""

    hostname, scheme = _url_parts(value.strip())
    lowered = value.casefold()
    evidence: list[Evidence] = []
    try:
        if hostname and ipaddress.ip_address(hostname):
            evidence.append(Evidence("ip_hostname", "Uses an IP address instead of a domain name."))
    except ValueError:
        pass
    if "xn--" in hostname:
        evidence.append(Evidence("punycode", "Uses an internationalized punycode hostname."))
    if "@" in value:
        evidence.append(Evidence("at_symbol", "Contains an @ symbol that can obscure the host."))
    if len(value) > 100:
        evidence.append(Evidence("long_url", "The URL is unusually long."))
    if len([label for label in hostname.split(".") if label]) > 4:
        evidence.append(Evidence("many_subdomains", "Uses an unusually deep subdomain structure."))
    if scheme != "https":
        evidence.append(Evidence("no_https", "Does not explicitly use HTTPS."))
    suspicious = sorted(
        token
        for token in ("account", "login", "password", "secure", "signin", "verify", "wallet")
        if token in lowered
    )
    if len(suspicious) >= 2:
        evidence.append(
            Evidence("suspicious_terms", "Contains several account or credential-related terms.")
        )
    return evidence


def _read_linear_pipeline(
    model: object,
) -> tuple[FeaturesTransformer, NDArray[np.float64], NDArray[np.str_]]:
    named_steps = getattr(model, "named_steps", None)
    if not isinstance(named_steps, dict):
        raise TypeError("Expected a fitted linear scikit-learn pipeline")
    features = named_steps.get("features")
    classifier = named_steps.get("classifier")
    if features is None or classifier is None:
        raise TypeError("Model pipeline is missing features or classifier")
    coefficients = np.asarray(getattr(classifier, "coef_", None), dtype=np.float64)
    if coefficients.ndim != 2 or coefficients.shape[0] != 1:
        raise TypeError("Expected a fitted binary linear classifier")
    typed_features = cast(FeaturesTransformer, features)
    names = np.asarray(typed_features.get_feature_names_out(), dtype=np.str_)
    return typed_features, coefficients[0], names


def feature_contributions(
    model: object, text: str, *, limit: int = 5
) -> tuple[list[FeatureContribution], list[FeatureContribution]]:
    """Return strongest phishing-supporting and mitigating active features."""

    features, coefficients, names = _read_linear_pipeline(model)
    transformed = cast(SparseFeatureMatrix, features.transform([text]))
    row = transformed.getrow(0)
    values = np.asarray(row.data, dtype=np.float64)
    indices = np.asarray(row.indices, dtype=np.int_)
    contributions = values * coefficients[indices]
    active = [
        FeatureContribution(_friendly_feature(str(names[index])), round(float(value), 6))
        for index, value in zip(indices, contributions, strict=True)
    ]
    supporting = sorted(
        (item for item in active if item.contribution > 0),
        key=lambda item: item.contribution,
        reverse=True,
    )[:limit]
    mitigating = sorted(
        (item for item in active if item.contribution < 0),
        key=lambda item: item.contribution,
    )[:limit]
    return supporting, mitigating


def _friendly_feature(value: str) -> str:
    prefix, _, feature = value.partition("__")
    if prefix == "word":
        cleaned = " ".join(feature.split())
        return f"word or phrase: {cleaned}"
    if prefix == "character":
        # Preserve word-boundary spaces so distinct character n-grams do not
        # collapse into the same human-readable label.
        return f"character pattern: {feature.replace(' ', '␠')}"
    if prefix == "lexical":
        return f"URL property: {feature.replace('_', ' ')}"
    return feature or value


def explain(
    content_type: str,
    text: str,
    base_model: BinaryProbabilisticModel,
    calibrated_model: CalibratedModel,
) -> dict[str, object]:
    """Create a complete, advisory, explainable detection result."""

    probability_matrix = np.asarray(calibrated_model.predict_proba([text]), dtype=np.float64)
    if probability_matrix.shape != (1, 2):
        raise ValueError("Expected one two-column calibrated probability")
    probability = float(probability_matrix[0, 1])
    decision = decide(probability)
    evidence = email_evidence(text) if content_type == "email" else url_evidence(text)
    supporting, mitigating = feature_contributions(base_model, text)
    reasons = [item.description for item in evidence[:4]]
    if not reasons and supporting and decision.classification == "phishing":
        reasons.append("Statistical patterns resemble examples learned by the phishing model.")
    if not reasons:
        reasons.append("No controlled-template warning sign was detected.")
    return {
        "content_type": content_type,
        "classification": decision.classification,
        "risk_score": decision.risk_score,
        "calibrated_probability": round(probability, 6),
        "recommended_action": decision.recommended_action,
        "guidance": decision.guidance,
        "reasons": reasons,
        "evidence": [asdict(item) for item in evidence],
        "supporting_model_features": [asdict(item) for item in supporting],
        "mitigating_model_features": [asdict(item) for item in mitigating],
        "model_version": __version__,
        "policy_version": decision.policy_version,
        "advisory_only": True,
        "safety_note": (
            "This advisory result can be wrong; verify important decisions through "
            "trusted channels."
        ),
    }
