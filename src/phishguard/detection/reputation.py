"""Conservative, reproducible hostname reputation safeguards."""

from __future__ import annotations

import csv
import hashlib
from importlib.resources import files
from urllib.parse import urlsplit

TRANCO_LIST_ID = "W3779"
TRANCO_GENERATED_DATE = "2026-08-09"
TRANCO_SOURCE_URL = "https://tranco-list.eu/list/W3779/1000000"
TRANCO_SNAPSHOT_SHA256 = "a6643a3a179c11aa14db551e9595f7d4410528eadb02b0330b4893525bf6aa78"
TRANCO_SNAPSHOT_SIZE = 1_000
KNOWN_HOST_PROBABILITY_CAP = 0.20


def _load_tranco_domains() -> dict[str, int]:
    """Load the pinned, packaged rank and domain pairs."""

    snapshot = files("phishguard.data").joinpath("tranco-W3779-top1000.csv")
    snapshot_bytes = snapshot.read_bytes()
    if hashlib.sha256(snapshot_bytes).hexdigest() != TRANCO_SNAPSHOT_SHA256:
        raise RuntimeError("Pinned Tranco reputation snapshot failed integrity verification")
    rows = csv.reader(snapshot_bytes.decode("utf-8").splitlines())
    domains = {domain.casefold(): int(rank) for rank, domain in rows}
    if len(domains) != TRANCO_SNAPSHOT_SIZE:
        raise RuntimeError("Pinned Tranco reputation snapshot has an unexpected size")
    return domains


TRANCO_TOP_DOMAINS = _load_tranco_domains()
REPUTABLE_HOSTS = frozenset(TRANCO_TOP_DOMAINS)


def normalize_url_input(value: str) -> tuple[str, bool]:
    """Assume HTTPS for a domain or URL whose scheme was omitted."""

    stripped = value.strip()
    if "://" not in stripped:
        return f"https://{stripped}", True
    return stripped, False


def reputable_https_host(value: str) -> str | None:
    """Return a ranked exact HTTPS host, allowing only a harmless www prefix."""

    try:
        normalized, _ = normalize_url_input(value)
        parsed = urlsplit(normalized)
        hostname = (parsed.hostname or "").casefold().rstrip(".")
    except ValueError:
        return None
    canonical = hostname.removeprefix("www.")
    if parsed.scheme.casefold() == "https" and canonical in REPUTABLE_HOSTS:
        return canonical
    return None
