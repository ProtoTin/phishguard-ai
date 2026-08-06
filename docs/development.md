# Development Guide

## Prerequisites

- Python 3.12 or newer
- Git
- Docker Desktop if using the container workflow

## Python environment

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Start the API

```bash
uvicorn phishguard.main:app --reload
```

Useful local endpoints:

- Service information: `http://localhost:8000/`
- Health check: `http://localhost:8000/health`
- Interactive API documentation: `http://localhost:8000/docs`
- OpenAPI schema: `http://localhost:8000/openapi.json`

The Phase 1 service contains operational endpoints only. Detection endpoints
will be introduced after the data and baseline-model phases.

## Quality checks

Run the same checks used by continuous integration:

```bash
ruff check .
ruff format --check .
mypy src tests
pytest
```

The test suite requires at least 90 percent statement coverage. New behavior
should include tests for both expected and invalid inputs.

## Configuration

Runtime settings use environment variables beginning with `PHISHGUARD_`. Copy
`.env.example` to `.env` for local overrides. The `.env` file is ignored by Git
and must never contain credentials that are committed to the repository.

## Docker workflow

Build and start the API:

```bash
docker compose up --build
```

Stop it with:

```bash
docker compose down
```

The production image runs as a non-root user with a read-only filesystem in the
Compose configuration.

## Repository conventions

- Application code lives under `src/phishguard/`.
- Tests mirror application behavior under `tests/`.
- Long-lived documentation belongs under `docs/`.
- Downloaded data and trained artifacts are not committed to Git.
- Each phase should result in a focused pull request or release milestone.
