"""FastAPI application entry point."""

from fastapi import FastAPI

from phishguard import __version__
from phishguard.config import get_settings
from phishguard.schemas import HealthResponse, ServiceInfoResponse


def create_app() -> FastAPI:
    """Build and configure the PhishGuard API."""

    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        summary="Explainable phishing-risk analysis",
        description=(
            "A defensive portfolio project. Detection endpoints will be added "
            "after the data and model phases are completed."
        ),
        version=__version__,
    )

    @application.get("/", response_model=ServiceInfoResponse, tags=["service"])
    def service_info() -> ServiceInfoResponse:
        """Return public service metadata."""

        return ServiceInfoResponse(
            name=settings.app_name,
            version=__version__,
            status="foundation_only",
            documentation="/docs",
        )

    @application.get("/health", response_model=HealthResponse, tags=["service"])
    def health() -> HealthResponse:
        """Report whether the API process is healthy."""

        return HealthResponse(
            status="healthy",
            service=settings.app_name,
            version=__version__,
            environment=settings.environment,
        )

    return application


app = create_app()
