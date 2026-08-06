# Data Directory

Raw and processed datasets are intentionally excluded from Git. This directory
contains only the versioned source manifest and instructions required to
reproduce them.

## Reproduction

From an activated development environment:

```bash
python scripts/download_data.py
python scripts/prepare_data.py
```

The first command downloads four pinned, checksum-verified files into
`data/raw/`. The second writes normalized JSON Lines files and a machine-readable
manifest under `data/processed/`, plus aggregate reports that contain no email
or URL samples.

## Local layout

```text
data/
├── sources.json        # committed source metadata and integrity values
├── raw/                # ignored publisher files
└── processed/          # ignored normalized JSONL splits and manifest
```

Do not commit files from `raw/` or `processed/`. Some records contain real
messages or malicious URL indicators. Treat every URL as inert text: do not
visit, resolve, crawl, or execute it.

See `docs/data-card.md` for provenance, labels, intended use, and limitations.
