"""Tests for bounded, advisory API endpoints and service status."""

import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response

from phishguard.config import Settings
from phishguard.main import create_app


class FixedAnalyzer:
    """Small detector double that records exactly what the route passes to it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def analyze(self, content_type: str, text: str) -> dict[str, object]:
        self.calls.append((content_type, text))
        return {
            "content_type": content_type,
            "classification": "phishing",
            "risk_score": 91,
            "calibrated_probability": 0.91,
            "recommended_action": "block",
            "guidance": "Block or isolate the content.",
            "reasons": ["Uses urgent language."],
            "evidence": [{"code": "urgent_language", "description": "Uses urgent language."}],
            "supporting_model_features": [
                {"feature": "word or phrase: verify", "contribution": 0.42}
            ],
            "mitigating_model_features": [],
            "model_version": "0.5.0",
            "policy_version": "2.0.0",
            "advisory_only": True,
            "safety_note": "This advisory result can be wrong.",
        }


def request(
    application: FastAPI,
    method: str,
    path: str,
    *,
    json: object | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    """Send a request directly to an ASGI application."""

    async def send() -> Response:
        transport = ASGITransport(app=application)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, json=json, headers=headers)

    return asyncio.run(send())


def test_service_info_and_health() -> None:
    application = create_app(detector=FixedAnalyzer(), settings=Settings(environment="test"))

    info = request(application, "GET", "/service")
    health = request(application, "GET", "/health")

    assert info.status_code == 200
    assert info.json() == {
        "name": "PhishGuard API",
        "version": "0.5.0",
        "status": "detection_api",
        "documentation": "/docs",
    }
    assert health.json() == {
        "status": "healthy",
        "service": "PhishGuard API",
        "version": "0.5.0",
        "environment": "test",
    }
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["referrer-policy"] == "no-referrer"


def test_dashboard_and_assets_use_safe_browser_controls() -> None:
    application = create_app(detector=FixedAnalyzer(), settings=Settings(environment="test"))

    dashboard = request(application, "GET", "/")
    stylesheet = request(application, "GET", "/assets/dashboard.css")
    script = request(application, "GET", "/assets/dashboard.js")

    assert dashboard.status_code == 200
    assert 'id="analysis-form"' in dashboard.text
    assert 'id="result-card"' in dashboard.text
    assert 'content="http://test/assets/og.png"' in dashboard.text
    assert "text/html" in dashboard.headers["content-type"]
    assert "default-src 'self'" in dashboard.headers["content-security-policy"]
    assert dashboard.headers["x-frame-options"] == "DENY"
    assert stylesheet.status_code == 200
    assert "text/css" in stylesheet.headers["content-type"]
    assert "https://" not in stylesheet.text
    assert script.status_code == 200
    assert "/v1/analyze/email" in script.text
    assert "/v1/analyze/url" in script.text
    assert "innerHTML" not in script.text


def test_readiness_and_analysis_routes_do_not_echo_input() -> None:
    detector = FixedAnalyzer()
    application = create_app(detector=detector, settings=Settings(environment="test"))
    submitted_email = "<script>alert(1)</script> Urgent password: private-value"
    submitted_url = "http://192.0.2.1/login/verify"

    ready = request(application, "GET", "/ready")
    email = request(application, "POST", "/v1/analyze/email", json={"content": submitted_email})
    url = request(application, "POST", "/v1/analyze/url", json={"url": submitted_url})

    assert ready.json() == {
        "status": "ready",
        "models": ["email", "url"],
        "policy_version": "2.0.0",
    }
    assert detector.calls == [("email", submitted_email), ("url", submitted_url)]
    assert email.status_code == 200
    assert url.status_code == 200
    assert email.json()["advisory_only"] is True
    assert url.json()["content_type"] == "url"
    assert submitted_email not in email.text
    assert submitted_url not in url.text
    assert email.headers["cache-control"] == "no-store"


def test_strict_validation_and_request_size_limit() -> None:
    application = create_app(detector=FixedAnalyzer(), settings=Settings(environment="test"))

    empty = request(application, "POST", "/v1/analyze/email", json={"content": "   "})
    extra = request(
        application,
        "POST",
        "/v1/analyze/url",
        json={"url": "https://example.test", "visit": True},
    )
    too_long = request(application, "POST", "/v1/analyze/url", json={"url": "x" * 2_049})
    too_large = request(
        application,
        "POST",
        "/v1/analyze/email",
        json={"content": "x" * 70_000},
    )
    invalid_length = request(
        application,
        "POST",
        "/v1/analyze/email",
        json={"content": "test"},
        headers={"content-length": "invalid"},
    )

    assert empty.status_code == 422
    assert extra.status_code == 422
    assert too_long.status_code == 422
    assert too_large.status_code == 413
    assert too_large.json() == {"detail": "Request body too large"}
    assert invalid_length.status_code == 400
    assert invalid_length.json() == {"detail": "Invalid Content-Length"}


def test_chunked_body_cannot_bypass_request_size_limit() -> None:
    application = create_app(detector=FixedAnalyzer(), settings=Settings(environment="test"))

    async def send_chunked() -> Response:
        async def chunks() -> Any:
            yield b'{"content":"'
            yield b"x" * 70_000
            yield b'"}'

        transport = ASGITransport(app=application)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(
                "/v1/analyze/email",
                content=chunks(),
                headers={"content-type": "application/json"},
            )

    response = asyncio.run(send_chunked())

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert response.headers["x-content-type-options"] == "nosniff"


def test_missing_artifacts_return_safe_unavailable_error(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        model_report_path=tmp_path / "missing-model-report.json",
        policy_path=tmp_path / "missing-policy.json",
    )
    application = create_app(settings=settings)

    dashboard = request(application, "GET", "/")
    response = request(application, "GET", "/ready")

    assert dashboard.status_code == 200
    assert response.status_code == 503
    body: dict[str, Any] = response.json()
    assert body == {
        "detail": "Detection models are unavailable; build and verify local artifacts first"
    }
    assert str(tmp_path) not in response.text
