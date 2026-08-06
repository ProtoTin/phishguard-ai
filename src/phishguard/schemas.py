"""API response schemas."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    """Service health information."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["healthy"]
    service: str
    version: str
    environment: str


class ServiceInfoResponse(BaseModel):
    """Public service metadata."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    status: Literal["foundation_only"]
    documentation: str
