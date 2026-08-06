"""FastAPI application entry point with bounded offline analysis routes."""

from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response

from phishguard import __version__
from phishguard.config import Settings, get_settings
from phishguard.detection.policy import POLICY_VERSION
from phishguard.detection.runtime import Analyzer, DetectionProvider, DetectionUnavailableError
from phishguard.middleware import RequestBodyLimitMiddleware
from phishguard.schemas import (
    AnalysisResponse,
    EmailAnalysisRequest,
    HealthResponse,
    ReadinessResponse,
    ServiceInfoResponse,
    URLAnalysisRequest,
)


def create_app(detector: Analyzer | None = None, settings: Settings | None = None) -> FastAPI:
    """Build and configure the PhishGuard API."""

    runtime_settings = settings or get_settings()
    application = FastAPI(
        title=runtime_settings.app_name,
        summary="Explainable phishing-risk analysis",
        description=(
            "A defensive portfolio project that analyzes submitted content offline. "
            "Results are advisory and may be incorrect."
        ),
        version=__version__,
    )
    application.state.detector_provider = DetectionProvider(
        runtime_settings.model_report_path,
        runtime_settings.policy_path,
        detector,
    )
    application.add_middleware(
        RequestBodyLimitMiddleware,
        max_bytes=runtime_settings.max_request_bytes,
    )

    @application.middleware("http")
    async def security_controls(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Add defensive headers without logging or echoing submitted content."""

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/v1/analyze/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def require_detector(request: Request) -> Analyzer:
        provider = request.app.state.detector_provider
        if not isinstance(provider, DetectionProvider):
            raise HTTPException(status_code=503, detail="Detection service is unavailable")
        try:
            return provider.get()
        except DetectionUnavailableError:
            raise HTTPException(
                status_code=503,
                detail="Detection models are unavailable; build and verify local artifacts first",
            ) from None

    @application.get("/", response_model=ServiceInfoResponse, tags=["service"])
    def service_info() -> ServiceInfoResponse:
        """Return public service metadata."""

        return ServiceInfoResponse(
            name=runtime_settings.app_name,
            version=__version__,
            status="detection_api",
            documentation="/docs",
        )

    @application.get("/health", response_model=HealthResponse, tags=["service"])
    def health() -> HealthResponse:
        """Report whether the API process is healthy."""

        return HealthResponse(
            status="healthy",
            service=runtime_settings.app_name,
            version=__version__,
            environment=runtime_settings.environment,
        )

    @application.get("/ready", response_model=ReadinessResponse, tags=["service"])
    def readiness(detector: Analyzer = Depends(require_detector)) -> ReadinessResponse:
        """Confirm that verified model artifacts are available for inference."""

        return ReadinessResponse(
            status="ready", models=["email", "url"], policy_version=POLICY_VERSION
        )

    @application.post(
        "/v1/analyze/email",
        response_model=AnalysisResponse,
        response_model_exclude_none=True,
        tags=["analysis"],
    )
    def analyze_email(
        payload: EmailAnalysisRequest,
        detector: Analyzer = Depends(require_detector),
    ) -> AnalysisResponse:
        """Analyze bounded email content as untrusted plain text."""

        return AnalysisResponse.model_validate(detector.analyze("email", payload.content))

    @application.post(
        "/v1/analyze/url",
        response_model=AnalysisResponse,
        response_model_exclude_none=True,
        tags=["analysis"],
    )
    def analyze_url(
        payload: URLAnalysisRequest,
        detector: Analyzer = Depends(require_detector),
    ) -> AnalysisResponse:
        """Analyze a URL string offline without resolving or visiting it."""

        return AnalysisResponse.model_validate(detector.analyze("url", payload.url))

    return application


app = create_app()
