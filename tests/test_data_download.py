"""Tests for safe, checksum-verified dataset downloads."""

import hashlib
import io
from pathlib import Path

import pytest

from phishguard.data import download
from phishguard.data.manifest import Checksum, DatasetSource


class FakeResponse(io.BytesIO):
    """Minimal context-managed HTTP response for downloader tests."""

    def __init__(self, content: bytes, content_length: int | None = None) -> None:
        super().__init__(content)
        self.headers = {} if content_length is None else {"Content-Length": str(content_length)}

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def make_source(content: bytes) -> DatasetSource:
    return DatasetSource(
        id="example",
        title="Example",
        content_type="email",
        role="development",
        format="zenodo_validation_csv",
        url="https://example.com/data.csv",
        filename="data.csv",
        expected_bytes=len(content),
        checksum=Checksum(
            algorithm="sha256",
            value=hashlib.sha256(content).hexdigest(),
            provenance="test",
        ),
        license="CC BY 4.0",
        license_url="https://creativecommons.org/licenses/by/4.0/",
        landing_page="https://example.com",
        citation="Example",
        label_mapping={"safe": "legitimate"},
        split_policy="train_validation",
    )


def test_downloads_and_reuses_verified_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"safe fixture"
    source = make_source(content)
    calls = 0

    def fake_urlopen(*args: object, **kwargs: object) -> FakeResponse:
        nonlocal calls
        calls += 1
        return FakeResponse(content, len(content))

    monkeypatch.setattr(download, "urlopen", fake_urlopen)
    first = download.download_source(source, tmp_path)
    second = download.download_source(source, tmp_path)

    assert first == second
    assert first.read_bytes() == content
    assert calls == 1
    assert download.file_digest(first, "sha256") == source.checksum.value


@pytest.mark.parametrize("change", ["size", "checksum"])
def test_verify_file_rejects_changed_artifact(tmp_path: Path, change: str) -> None:
    content = b"expected"
    source = make_source(content)
    path = tmp_path / source.filename
    path.write_bytes(b"wrong" if change == "size" else b"differed")
    expected_bytes = source.expected_bytes if change == "checksum" else len(content)

    with pytest.raises(ValueError, match="mismatch"):
        download.verify_file(path, source.checksum, expected_bytes)


def test_rejects_oversized_declared_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_source(b"content")
    monkeypatch.setattr(
        download,
        "urlopen",
        lambda *args, **kwargs: FakeResponse(b"", download.MAX_DOWNLOAD_BYTES + 1),
    )

    with pytest.raises(ValueError, match="larger"):
        download.download_source(source, tmp_path, force=True)

    assert not list(tmp_path.rglob("*.part"))
