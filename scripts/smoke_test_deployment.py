"""Run non-destructive smoke checks against a deployed PhishGuard service."""

from __future__ import annotations

import argparse
import json
from email.message import Message
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "https://phishguard-ai-prototin.onrender.com/"
BENIGN_URL = "youtube.com"
DECEPTIVE_URL = "http://192.0.2.10/login/verify-account/password"
DECEPTIVE_EMAIL = (
    "URGENT: Your payroll account is locked. Verify your password immediately at the "
    "attached login page or access will be terminated."
)


def validate_base_url(value: str) -> str:
    """Require an HTTPS origin with no credentials, query, or fragment."""

    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("base URL must be a credential-free HTTPS origin")
    return value.rstrip("/") + "/"


def request(
    base_url: str,
    path: str,
    *,
    payload: dict[str, object] | None = None,
) -> tuple[int, Message, bytes]:
    """Send one bounded request and return controlled HTTP error responses."""

    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {} if body is None else {"Content-Type": "application/json"}
    operation = Request(  # noqa: S310 - base URL is restricted to HTTPS
        urljoin(base_url, path.lstrip("/")), data=body, headers=headers
    )
    try:
        with urlopen(operation, timeout=60) as response:  # noqa: S310 - HTTPS validated above
            return response.status, response.headers, response.read()
    except HTTPError as error:
        return error.code, error.headers, error.read()


def json_body(body: bytes) -> dict[str, Any]:
    """Decode an expected JSON object."""

    value = json.loads(body)
    if not isinstance(value, dict):
        raise AssertionError("expected a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    """Raise a concise smoke-test failure."""

    if not condition:
        raise AssertionError(message)


def run(base_url: str) -> dict[str, object]:
    """Verify availability, security headers, inference, and validation behavior."""

    root_status, root_headers, root_body = request(base_url, "/")
    require(root_status == 200 and b"PhishGuard" in root_body, "dashboard is unavailable")
    required_headers = {
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    }
    require(required_headers <= {name.casefold() for name in root_headers}, "headers are missing")

    health_status, _, health_raw = request(base_url, "/health")
    health = json_body(health_raw)
    require(health_status == 200 and health.get("environment") == "production", "health failed")

    ready_status, _, ready_raw = request(base_url, "/ready")
    ready = json_body(ready_raw)
    require(ready_status == 200 and ready.get("models") == ["email", "url"], "ready failed")

    benign_status, benign_headers, benign_raw = request(
        base_url, "/v1/analyze/url", payload={"url": BENIGN_URL}
    )
    benign = json_body(benign_raw)
    require(benign_status == 200, "benign URL analysis failed")
    require(benign.get("classification") == "legitimate", "benign URL false positive")
    require(benign_headers.get("Cache-Control") == "no-store", "analysis caching is enabled")
    require(BENIGN_URL.encode() not in benign_raw, "response echoes the submitted URL")

    deceptive_status, _, deceptive_raw = request(
        base_url, "/v1/analyze/url", payload={"url": DECEPTIVE_URL}
    )
    deceptive = json_body(deceptive_raw)
    require(deceptive_status == 200, "deceptive URL analysis failed")
    require(deceptive.get("classification") == "phishing", "deceptive URL was not identified")
    require(DECEPTIVE_URL.encode() not in deceptive_raw, "response echoes the deceptive URL")

    email_status, _, email_raw = request(
        base_url, "/v1/analyze/email", payload={"content": DECEPTIVE_EMAIL}
    )
    email = json_body(email_raw)
    require(email_status == 200, "deceptive email analysis failed")
    require(email.get("classification") in {"suspicious", "phishing"}, "email was allowed")
    require(email.get("recommended_action") != "allow", "email action was allow")
    require(DECEPTIVE_EMAIL.encode() not in email_raw, "response echoes the submitted email")

    invalid_status, _, _ = request(
        base_url,
        "/v1/analyze/url",
        payload={"url": "https://example.test", "visit": True},
    )
    require(invalid_status == 422, "strict input validation failed")

    return {
        "base_url": base_url,
        "health": health.get("status"),
        "ready_policy": ready.get("policy_version"),
        "benign_url": [benign.get("classification"), benign.get("risk_score")],
        "deceptive_url": [deceptive.get("classification"), deceptive.get("risk_score")],
        "deceptive_email": [email.get("classification"), email.get("risk_score")],
        "security_headers": "present",
        "strict_validation": "present",
    }


def main() -> None:
    """Run the deployment smoke test from the command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args()
    print(json.dumps(run(validate_base_url(args.base_url)), indent=2))


if __name__ == "__main__":
    main()
