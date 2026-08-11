"""Production server entry point with platform-aware port selection."""

import os

import uvicorn


def get_port() -> int:
    """Return the hosting-platform port, falling back to the local default."""

    raw_port = os.getenv("PORT", "8000")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise ValueError("PORT must be an integer") from error
    if not 1 <= port <= 65_535:
        raise ValueError("PORT must be between 1 and 65535")
    return port


def main() -> None:
    """Run the production ASGI server on the assigned port."""

    uvicorn.run(
        "phishguard.main:app",
        host="0.0.0.0",  # noqa: S104 - required for container ingress
        port=get_port(),
    )


if __name__ == "__main__":
    main()
