"""Strict API request and response schemas."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Classification = Literal["legitimate", "unverified", "suspicious", "phishing"]
RecommendedAction = Literal["allow", "warn", "quarantine", "block"]


class StrictSchema(BaseModel):
    """Shared schema behavior for public API objects."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EmailAnalysisRequest(StrictSchema):
    """Bounded email text accepted for offline analysis."""

    content: str = Field(min_length=1, max_length=50_000)


class URLAnalysisRequest(StrictSchema):
    """Bounded URL string accepted for offline analysis."""

    url: str = Field(min_length=1, max_length=2_048)


class EvidenceResponse(StrictSchema):
    """One controlled, deterministic warning sign."""

    code: str
    description: str


class FeatureContributionResponse(StrictSchema):
    """One active model feature and its signed contribution."""

    feature: str
    contribution: float


class AnalysisResponse(StrictSchema):
    """Complete advisory phishing-analysis response."""

    content_type: Literal["email", "url"]
    classification: Classification
    risk_score: int = Field(ge=0, le=100)
    calibrated_probability: float = Field(ge=0.0, le=1.0)
    recommended_action: RecommendedAction
    guidance: str
    reasons: list[str]
    evidence: list[EvidenceResponse]
    supporting_model_features: list[FeatureContributionResponse]
    mitigating_model_features: list[FeatureContributionResponse]
    model_version: str
    policy_version: str
    advisory_only: Literal[True]
    safety_note: str


class HealthResponse(StrictSchema):
    """Service health information."""

    status: Literal["healthy"]
    service: str
    version: str
    environment: str


class ReadinessResponse(StrictSchema):
    """Whether verified model artifacts can serve predictions."""

    status: Literal["ready"]
    models: list[Literal["email", "url"]]
    policy_version: str


class ServiceInfoResponse(StrictSchema):
    """Public service metadata."""

    name: str
    version: str
    status: Literal["detection_api"]
    documentation: str
