"""Conservative, transparent hostname reputation safeguards."""

from __future__ import annotations

from urllib.parse import urlsplit

# Exact hosts only. This deliberately does not trust lookalike domains or arbitrary
# subdomains. The short list also doubles as an out-of-source benign regression set.
KNOWN_BENIGN_HOSTS = frozenset(
    {
        "apple.com",
        "docs.python.org",
        "github.com",
        "google.com",
        "linkedin.com",
        "microsoft.com",
        "nasa.gov",
        "wikipedia.org",
    }
)
KNOWN_HOST_PROBABILITY_CAP = 0.20


def known_benign_https_host(value: str) -> str | None:
    """Return a configured exact HTTPS host, allowing only a harmless www prefix."""

    try:
        parsed = urlsplit(value.strip() if "://" in value else f"http://{value.strip()}")
        hostname = (parsed.hostname or "").casefold().rstrip(".")
    except ValueError:
        return None
    canonical = hostname.removeprefix("www.")
    if parsed.scheme.casefold() == "https" and canonical in KNOWN_BENIGN_HOSTS:
        return canonical
    return None
