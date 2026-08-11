"""Versioned risk-score bands and advisory prevention decisions."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import asdict, dataclass
from typing import Literal

from phishguard.detection.reputation import (
    KNOWN_HOST_PROBABILITY_CAP,
    TRANCO_GENERATED_DATE,
    TRANCO_LIST_ID,
    TRANCO_SNAPSHOT_SHA256,
    TRANCO_SNAPSHOT_SIZE,
    TRANCO_SOURCE_URL,
)

Classification = Literal["legitimate", "unverified", "suspicious", "phishing"]
RecommendedAction = Literal["allow", "warn", "quarantine", "block"]


@dataclass(frozen=True)
class PolicyBand:
    """One inclusive risk-score band."""

    minimum: int
    maximum: int
    classification: Classification
    action: RecommendedAction
    guidance: str


@dataclass(frozen=True)
class PolicyDecision:
    """Advisory action produced from a calibrated probability."""

    risk_score: int
    classification: Classification
    recommended_action: RecommendedAction
    guidance: str
    policy_version: str


POLICY_VERSION = "2.1.0"
UNVERIFIED_MINIMUM_SCORE = 30
UNVERIFIED_MAXIMUM_SCORE = 59
EMAIL_WARNING_MINIMUM_SCORE = 30
EMAIL_WARNING_EVIDENCE_COMBINATIONS = (
    frozenset({"urgent_language", "credential_request"}),
    frozenset({"account_verification", "credential_request"}),
    frozenset({"link_prompt", "credential_request"}),
    frozenset({"urgent_language", "payment_request"}),
)
POLICY_BANDS = (
    PolicyBand(
        0,
        29,
        "legitimate",
        "allow",
        "No strong phishing signal was detected; continue normal caution.",
    ),
    PolicyBand(
        30,
        59,
        "suspicious",
        "warn",
        "Treat the content cautiously and verify it through a trusted channel.",
    ),
    PolicyBand(
        60,
        84,
        "phishing",
        "quarantine",
        "Do not interact with the content; send it for security review.",
    ),
    PolicyBand(
        85,
        100,
        "phishing",
        "block",
        "Block or isolate the content, subject to organizational review policy.",
    ),
)


def risk_score(probability: float) -> int:
    """Convert a bounded calibrated probability to an integer score."""

    bounded = min(1.0, max(0.0, float(probability)))
    return min(100, int(bounded * 100 + 0.5))


def decide(probability: float) -> PolicyDecision:
    """Map a calibrated probability into an advisory policy decision."""

    score = risk_score(probability)
    for band in POLICY_BANDS:
        if band.minimum <= score <= band.maximum:
            return PolicyDecision(
                risk_score=score,
                classification=band.classification,
                recommended_action=band.action,
                guidance=band.guidance,
                policy_version=POLICY_VERSION,
            )
    raise RuntimeError(f"No policy band contains risk score {score}")


def decide_unverified(probability: float) -> PolicyDecision:
    """Return an uncertainty decision when URL-only evidence cannot support a verdict."""

    score = min(
        UNVERIFIED_MAXIMUM_SCORE,
        max(UNVERIFIED_MINIMUM_SCORE, risk_score(probability)),
    )
    return PolicyDecision(
        risk_score=score,
        classification="unverified",
        recommended_action="warn",
        guidance=(
            "The offline detector cannot verify this domain; confirm it through a trusted "
            "source before entering sensitive information."
        ),
        policy_version=POLICY_VERSION,
    )


def decide_email(probability: float, evidence_codes: Collection[str]) -> PolicyDecision:
    """Prevent corroborated email warning signs from receiving an allow decision."""

    codes = frozenset(evidence_codes)
    if any(combination <= codes for combination in EMAIL_WARNING_EVIDENCE_COMBINATIONS):
        return decide(max(probability, EMAIL_WARNING_MINIMUM_SCORE / 100))
    return decide(probability)


def policy_document() -> dict[str, object]:
    """Return the stable policy definition for JSON serialization."""

    return {
        "policy_version": POLICY_VERSION,
        "score_interpretation": (
            "evidence-aware calibrated score; conservative email and URL safeguards "
            "prevent unsupported allow or phishing verdicts"
        ),
        "advisory_only": True,
        "email_evidence_floor": {
            "condition": "at least one reviewed combination of corroborating warning signs",
            "minimum_score": EMAIL_WARNING_MINIMUM_SCORE,
            "classification": "suspicious",
            "action": "warn",
            "combinations": [
                sorted(combination) for combination in EMAIL_WARNING_EVIDENCE_COMBINATIONS
            ],
            "limitation": (
                "The safeguard prevents an allow result but does not declare the email phishing."
            ),
        },
        "known_https_host_mitigation": {
            "match": "exact hostname after removing an optional www prefix",
            "maximum_probability": KNOWN_HOST_PROBABILITY_CAP,
            "source": "Tranco top-1000 popularity ranking",
            "source_list_id": TRANCO_LIST_ID,
            "source_generated_date": TRANCO_GENERATED_DATE,
            "source_url": TRANCO_SOURCE_URL,
            "snapshot_file": "phishguard/data/tranco-W3779-top1000.csv",
            "snapshot_sha256": TRANCO_SNAPSHOT_SHA256,
            "host_count": TRANCO_SNAPSHOT_SIZE,
            "limitation": "Popularity reduces false positives but does not prove a page is safe.",
        },
        "unverified_url_policy": {
            "condition": (
                "hostname absent from the offline reputation snapshot and no concrete "
                "phishing indicator detected"
            ),
            "score_range": [UNVERIFIED_MINIMUM_SCORE, UNVERIFIED_MAXIMUM_SCORE],
            "classification": "unverified",
            "action": "warn",
            "limitation": "Live reputation and page contents are not checked.",
        },
        "bands": [asdict(band) for band in POLICY_BANDS],
    }
