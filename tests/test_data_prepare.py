"""Tests for normalization, deduplication, splitting, and reporting."""

import csv
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from openpyxl import Workbook

from phishguard.data.manifest import Checksum, DatasetSource
from phishguard.data.prepare import (
    RawRecord,
    SourceStats,
    assign_split,
    canonical_email,
    canonical_url,
    deduplicate,
    load_curated_email_csv,
    load_phiusiil_zip,
    load_social_engineering_xlsx,
    load_validation_csv,
    prepare_all,
    process_records,
    require_dict,
)


def make_source(
    *,
    source_id: str,
    content_type: str,
    source_format: str,
    filename: str,
    labels: dict[str, str],
    policy: str,
) -> DatasetSource:
    return DatasetSource(
        id=source_id,
        title=source_id,
        content_type=content_type,  # type: ignore[arg-type]
        role="external_test" if policy == "external_test" else "development",
        format=source_format,  # type: ignore[arg-type]
        url=f"https://example.com/{filename}",
        filename=filename,
        expected_bytes=0,
        checksum=Checksum(algorithm="sha256", value="", provenance="test"),
        license="CC BY 4.0",
        license_url="https://creativecommons.org/licenses/by/4.0/",
        landing_page="https://example.com",
        citation="Example",
        label_mapping=labels,  # type: ignore[arg-type]
        split_policy=policy,  # type: ignore[arg-type]
    )


def write_xlsx(path: Path) -> None:
    workbook = Workbook()
    worksheet = workbook.active
    if worksheet is None:
        raise RuntimeError("Test workbook contains no active worksheet")
    worksheet.append(["Corpus", "Labels"])
    worksheet.append(["Reset your password now\tPhishing"])
    worksheet.append(["Weekly team update\tNOT-Malicious General Class"])
    worksheet.append(["Download this executable\tMalware"])
    workbook.save(path)


def write_validation_csv(path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["Email Text", "Email Type"])
        writer.writerow(["Invoice attached", "Safe Email"])
        writer.writerow(["Verify your account immediately", "Phishing Email"])


def write_curated_csv(path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["subject", "body", "label"])
        writer.writerow(["Team update", "The meeting starts at ten.", "0"])
        writer.writerow(["Account alert", "Verify your password now.", "1"])


def write_url_zip(path: Path) -> None:
    rows = [
        ["URL", "Domain", "label"],
        ["https://safe.example/home", "safe.example", "1"],
        ["http://login.bad.example/a", "login.bad.example", "0"],
        ["http://login.bad.example/b", "login.bad.example", "0"],
    ]
    content = "\n".join(",".join(row) for row in rows) + "\n"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("PhiUSIIL_Phishing_URL_Dataset.csv", content)


def test_canonicalization_is_offline_and_stable() -> None:
    assert canonical_email("  HéLLo,   WORLD! ") == canonical_email("héllo world")
    assert canonical_url("HTTPS://WWW.Example.COM:443/a//b/?z=2&x=1#frag") == (
        "//example.com/a/b?x=1&z=2"
    )


def test_deduplication_removes_duplicates_and_conflicts() -> None:
    records = [
        RawRecord("email", "Hello!", "legitimate", "source", "1", "one", "train_validation"),
        RawRecord("email", " hello ", "legitimate", "source", "2", "one", "train_validation"),
        RawRecord("email", "HELLO", "phishing", "source", "3", "one", "train_validation"),
        RawRecord("email", "Different", "phishing", "source", "4", "one", "train_validation"),
    ]

    unique, duplicates, conflicts = deduplicate(records)

    assert [record.text for record in unique] == ["Different"]
    assert duplicates == 1
    assert conflicts == 1


def test_grouped_split_is_deterministic() -> None:
    first = RawRecord(
        "url",
        "https://example.com",
        "legitimate",
        "source",
        "1",
        "example.com",
        "train_validation_test",
    )
    second = RawRecord(
        "url",
        "https://example.com/path",
        "legitimate",
        "source",
        "2",
        "example.com",
        "train_validation_test",
    )

    assert assign_split(first, 42) == assign_split(second, 42)
    assert process_records([first], 42)[0].split == assign_split(first, 42)
    external = RawRecord(
        "url",
        "https://example.com/external",
        "legitimate",
        "source",
        "3",
        "example.com",
        "external_test",
    )
    assert assign_split(external, 42) == "external_test"


def test_source_specific_loaders(tmp_path: Path) -> None:
    curated_path = tmp_path / "curated.csv"
    xlsx_path = tmp_path / "training.xlsx"
    validation_path = tmp_path / "validation.csv"
    url_path = tmp_path / "urls.zip"
    write_curated_csv(curated_path)
    write_xlsx(xlsx_path)
    write_validation_csv(validation_path)
    write_url_zip(url_path)

    curated_source = make_source(
        source_id="curated",
        content_type="email",
        source_format="curated_email_csv",
        filename=curated_path.name,
        labels={"0": "legitimate", "1": "phishing"},
        policy="train_validation",
    )
    xlsx_source = make_source(
        source_id="training",
        content_type="email",
        source_format="zenodo_tsv_in_xlsx",
        filename=xlsx_path.name,
        labels={
            "Phishing": "phishing",
            "NOT-Malicious General Class": "legitimate",
        },
        policy="train_validation",
    )
    validation_source = make_source(
        source_id="external",
        content_type="email",
        source_format="zenodo_validation_csv",
        filename=validation_path.name,
        labels={"Safe Email": "legitimate", "Phishing Email": "phishing"},
        policy="external_test",
    )
    url_source = make_source(
        source_id="urls",
        content_type="url",
        source_format="uci_phiusiil_zip_csv",
        filename=url_path.name,
        labels={"0": "phishing", "1": "legitimate"},
        policy="train_validation_test",
    )

    curated_stats = SourceStats()
    xlsx_stats = SourceStats()
    validation_stats = SourceStats()
    url_stats = SourceStats()
    assert len(list(load_curated_email_csv(curated_source, curated_path, curated_stats))) == 2
    assert len(list(load_social_engineering_xlsx(xlsx_source, xlsx_path, xlsx_stats))) == 2
    assert xlsx_stats.excluded_labels == 1
    assert len(list(load_validation_csv(validation_source, validation_path, validation_stats))) == 2
    assert len(list(load_phiusiil_zip(url_source, url_path, url_stats))) == 3


def manifest_source(source: DatasetSource, path: Path) -> dict[str, object]:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "id": source.id,
        "title": source.title,
        "content_type": source.content_type,
        "role": source.role,
        "format": source.format,
        "url": source.url,
        "filename": source.filename,
        "expected_bytes": path.stat().st_size,
        "checksum": {
            "algorithm": "sha256",
            "value": digest,
            "provenance": "test",
        },
        "license": source.license,
        "license_url": source.license_url,
        "landing_page": source.landing_page,
        "citation": source.citation,
        "label_mapping": source.label_mapping,
        "split_policy": source.split_policy,
    }


def test_complete_miniature_pipeline(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    output_dir = tmp_path / "processed"
    report_json = tmp_path / "report.json"
    report_markdown = tmp_path / "report.md"
    specifications = [
        make_source(
            source_id="training",
            content_type="email",
            source_format="zenodo_tsv_in_xlsx",
            filename="training.xlsx",
            labels={
                "Phishing": "phishing",
                "NOT-Malicious General Class": "legitimate",
            },
            policy="train_validation",
        ),
        make_source(
            source_id="external",
            content_type="email",
            source_format="zenodo_validation_csv",
            filename="external.csv",
            labels={"Safe Email": "legitimate", "Phishing Email": "phishing"},
            policy="external_test",
        ),
        make_source(
            source_id="urls",
            content_type="url",
            source_format="uci_phiusiil_zip_csv",
            filename="urls.zip",
            labels={"0": "phishing", "1": "legitimate"},
            policy="train_validation_test",
        ),
    ]
    writers = [write_xlsx, write_validation_csv, write_url_zip]
    source_documents = []
    for source, writer in zip(specifications, writers, strict=True):
        source_dir = raw_dir / source.id
        source_dir.mkdir(parents=True)
        source_path = source_dir / source.filename
        writer(source_path)
        source_documents.append(manifest_source(source, source_path))
    manifest_path = tmp_path / "sources.json"
    manifest_path.write_text(
        json.dumps({"manifest_version": 1, "sources": source_documents}),
        encoding="utf-8",
    )

    report = prepare_all(
        manifest_path,
        raw_dir,
        output_dir,
        report_json,
        report_markdown,
        seed=42,
    )

    processed = require_dict(report["processed"], "processed")
    assert processed["total_records"] == 7
    assert report_json.exists()
    assert "Total processed records: **7**" in report_markdown.read_text()
    assert (output_dir / "manifest.json").exists()
    assert sum(len(path.read_text().splitlines()) for path in output_dir.glob("*.jsonl")) == 7
    group_splits: dict[str, set[str]] = {}
    for path in output_dir.glob("*.jsonl"):
        for line in path.read_text().splitlines():
            record = json.loads(line)
            group_splits.setdefault(record["group_id"], set()).add(record["split"])
    assert all(len(splits) == 1 for splits in group_splits.values())


def test_require_dict_rejects_invalid_report_shape() -> None:
    with pytest.raises(TypeError, match="Expected report"):
        require_dict([], "report")
