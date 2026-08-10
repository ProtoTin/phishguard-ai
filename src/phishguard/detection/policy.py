"""Versioned risk-score bands and advisory prevention decisions."""

from __future__ import annotations

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

Classification = Literal["legitimate", "suspicious", "phishing"]
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


POLICY_VERSION = "1.2.0"
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


def policy_document() -> dict[str, object]:
    """Return the stable policy definition for JSON serialization."""

    return {
        "policy_version": POLICY_VERSION,
        "score_interpretation": (
            "rounded calibrated phishing probability multiplied by 100, after documented "
            "exact-host mitigation"
        ),
        "advisory_only": True,
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
        "bands": [asdict(band) for band in POLICY_BANDS],
    }
