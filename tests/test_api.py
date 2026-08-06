"""Tests for the application service endpoints."""

import asyncio

from httpx import ASGITransport, AsyncClient, Response

from phishguard.main import app


def request(path: str) -> Response:
    """Send a request directly to the ASGI application."""

    async def send() -> Response:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get(path)

    return asyncio.run(send())


def test_service_info() -> None:
    response = request("/")

    assert response.status_code == 200
    assert response.json() == {
        "name": "PhishGuard API",
        "version": "0.2.0",
        "status": "foundation_only",
        "documentation": "/docs",
    }


def test_health_check() -> None:
    response = request("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "PhishGuard API",
        "version": "0.2.0",
        "environment": "development",
    }
