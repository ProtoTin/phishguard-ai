"""Checksum-verified dataset downloader."""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path
from urllib.request import Request, urlopen

from phishguard.data.manifest import Checksum, DatasetSource, load_sources

CHUNK_BYTES = 1024 * 1024
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024


def file_digest(path: Path, algorithm: str) -> str:
    """Calculate a supported digest without loading the file into memory."""

    digest = hashlib.new(algorithm)
    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, checksum: Checksum, expected_bytes: int) -> None:
    """Raise when a downloaded file differs from the pinned source artifact."""

    actual_bytes = path.stat().st_size
    if actual_bytes != expected_bytes:
        raise ValueError(
            f"Size mismatch for {path.name}: expected {expected_bytes}, got {actual_bytes}"
        )
    actual_digest = file_digest(path, checksum.algorithm)
    if actual_digest != checksum.value:
        raise ValueError(
            f"Checksum mismatch for {path.name}: expected {checksum.value}, got {actual_digest}"
        )


def download_source(source: DatasetSource, raw_dir: Path, *, force: bool = False) -> Path:
    """Download one declared source atomically and verify its integrity."""

    destination_dir = raw_dir / source.id
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / source.filename
    if destination.exists() and not force:
        verify_file(destination, source.checksum, source.expected_bytes)
        return destination

    temporary = destination.with_suffix(destination.suffix + ".part")
    temporary.unlink(missing_ok=True)
    request = Request(  # noqa: S310 -- manifest validation permits HTTPS only
        source.url, headers={"User-Agent": "PhishGuard-Data-Pipeline/0.1"}
    )
    try:
        with urlopen(request, timeout=60) as response, temporary.open("wb") as output:  # noqa: S310
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"Refusing download larger than {MAX_DOWNLOAD_BYTES} bytes")
            shutil.copyfileobj(response, output, length=CHUNK_BYTES)
        if temporary.stat().st_size > MAX_DOWNLOAD_BYTES:
            raise ValueError(f"Downloaded file exceeds {MAX_DOWNLOAD_BYTES} bytes")
        verify_file(temporary, source.checksum, source.expected_bytes)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def download_all(manifest_path: Path, raw_dir: Path, *, force: bool = False) -> list[Path]:
    """Download every source in the manifest."""

    return [download_source(source, raw_dir, force=force) for source in load_sources(manifest_path)]


def main() -> None:
    """Run the dataset downloader from the command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("data/sources.json"))
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    paths = download_all(args.manifest, args.raw_dir, force=args.force)
    for path in paths:
        print(f"verified {path}")


if __name__ == "__main__":
    main()
