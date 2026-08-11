"""Small ASGI security middleware with no third-party service dependency."""

from __future__ import annotations

import math
import time
from collections import deque

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

ANALYSIS_PATHS = frozenset({"/v1/analyze/email", "/v1/analyze/url"})


class AnalysisRateLimitMiddleware:
    """Bound analysis requests per network peer in a single service process."""

    def __init__(self, app: ASGIApp, max_requests: int, window_seconds: int) -> None:
        self.app = app
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = {}
        self._last_cleanup = time.monotonic()

    @staticmethod
    def _client_key(scope: Scope) -> str:
        client = scope.get("client")
        if isinstance(client, tuple) and client:
            return str(client[0])
        return "unknown"

    def _remove_stale_clients(self, now: float) -> None:
        if now - self._last_cleanup < self.window_seconds:
            return
        cutoff = now - self.window_seconds
        self._requests = {
            client: requests
            for client, requests in self._requests.items()
            if requests and requests[-1] > cutoff
        }
        self._last_cleanup = now

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path") not in ANALYSIS_PATHS
        ):
            await self.app(scope, receive, send)
            return

        now = time.monotonic()
        self._remove_stale_clients(now)
        cutoff = now - self.window_seconds
        requests = self._requests.setdefault(self._client_key(scope), deque())
        while requests and requests[0] <= cutoff:
            requests.popleft()

        if len(requests) >= self.max_requests:
            retry_after = max(1, math.ceil(requests[0] + self.window_seconds - now))
            await JSONResponse(
                status_code=429,
                content={"detail": "Analysis rate limit exceeded; retry later"},
                headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
            )(scope, receive, send)
            return

        requests.append(now)
        await self.app(scope, receive, send)


class RequestBodyLimitMiddleware:
    """Bound request bodies even when a client omits Content-Length."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, scope: Scope, receive: Receive, send: Send, status: int) -> None:
        detail = "Request body too large" if status == 413 else "Invalid Content-Length"
        await JSONResponse(status_code=status, content={"detail": detail})(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        declared_length = headers.get(b"content-length")
        if declared_length is not None:
            try:
                if int(declared_length) > self.max_bytes:
                    await self._reject(scope, receive, send, 413)
                    return
            except ValueError:
                await self._reject(scope, receive, send, 400)
                return

        messages: list[Message] = []
        received_bytes = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_bytes:
                    await self._reject(scope, receive, send, 413)
                    return
                if not message.get("more_body", False):
                    break

        async def replay() -> Message:
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)
