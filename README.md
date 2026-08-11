# AI Phishing Detection and Prevention System

An explainable phishing-risk analysis system for email content and URLs. The
project combines machine-learning models with deterministic security rules
to identify suspicious messages, explain the warning signs, and recommend a
proportionate response.

![PhishGuard — Explainable phishing analysis](src/phishguard/static/og.png)

> **Project status:** Phase 7 complete — the hardened dashboard, API, Policy 2.1,
> and four digest-verified model artifacts are live in a reproducible Render
> deployment. The public release passed the documented production smoke suite.

**[Open the live PhishGuard demo](https://phishguard-ai-prototin.onrender.com/)**

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ProtoTin/phishguard-ai)

## Project goals

- Analyze pasted email content and standalone URLs without visiting links.
- Return a `legitimate`, `unverified`, `suspicious`, or `phishing` classification.
- Provide a calibrated risk score from 0 to 100.
- Explain the signals that influenced each result.
- Recommend whether to allow, warn, quarantine, or block.
- Demonstrate reproducible ML, secure API design, automated tests, and
  deployment practices in a portfolio-ready project.

## User experience

1. A user pastes an email or URL into the web interface.
2. The service safely parses the submitted content.
3. Rules and ML models evaluate text, sender, and URL characteristics.
4. The user receives a risk score, human-readable reasons, and a recommended
   action.
5. Optional feedback can be used to evaluate future model versions without
   storing sensitive email content by default.

## Initial detection coverage

- Credential-theft and account-takeover messages
- Sender and brand impersonation
- Deceptive, obfuscated, and suspicious URLs
- Urgency, fear, reward, and payment-based social engineering
- Requests for passwords, payment, or other sensitive information
- Suspicious attachment names and HTML form indicators

## Safety principles

- Submitted URLs are parsed as text and never automatically opened.
- Email HTML is treated as untrusted input and is never rendered directly.
- Raw private email content is not retained by default.
- A low risk score is not presented as proof that content is safe.
- Automated blocking will not be enabled until performance and false-positive
  behavior are evaluated.

## Architecture

```text
Web interface
      |
      v
FastAPI analysis service
      |
      +--> Safe email and URL parsing
      +--> Rule-based security signals
      +--> Email text model
      +--> URL feature model
      +--> Risk scoring and explanation engine
      |
      v
Classification + score + reasons + recommended action
```

## Documentation

- [Project scope](docs/project-scope.md)
- [Threat model](docs/threat-model.md)
- [Development guide](docs/development.md)
- [Data card](docs/data-card.md)
- [Latest data-quality report](docs/data-quality-report.md)
- [Model card](docs/model-card.md)
- [URL reputation and normalization](docs/url-reputation.md)
- [Baseline evaluation](docs/model-evaluation.md)
- [Explanation and prevention-policy evaluation](docs/explanations-and-policy.md)
- [API guide](docs/api.md)
- [Dashboard guide](docs/dashboard.md)
- [Production hardening](docs/production-hardening.md)
- [Public deployment](docs/deployment.md)
- [Production verification report](docs/production-verification.md)

## Local development

### Requirements

- Python 3.12+
- Git
- Docker Desktop (optional)

### Run with Python

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
uvicorn phishguard.main:app --reload
```

Open `http://localhost:8000/` for the analysis dashboard, `/docs` for interactive
API documentation, or `/ready` to verify that the hashed model artifacts are
loaded. A fresh clone includes the four reviewed deployment artifacts; the data,
training, and policy-build steps below are only required to reproduce or replace them.

### Run the checks

```bash
ruff check .
ruff format --check .
mypy src tests
pytest
```

### Run with Docker

```bash
docker compose up --build
```

The API will be available at `http://localhost:8000`.

## Reproduce the dataset

Install the data-pipeline dependency, download the pinned source files, and
prepare the normalized splits:

```bash
python -m pip install -e ".[data]"
python scripts/download_data.py
python scripts/prepare_data.py
```

Downloaded source data and processed records remain outside Git. The source
manifest, attribution, checksums, data card, and aggregate quality report are
versioned in the repository. The pipeline never opens or visits URLs contained
inside the datasets.

## Train the baseline models

After reproducing the processed dataset, install the ML dependency and run:

```bash
python -m pip install -e ".[ml]"
python scripts/train_models.py
```

This trains separate email and URL classifiers, selects thresholds on validation
data, evaluates untouched test data, and writes model artifacts under `artifacts/`.
The four reviewed deployment artifacts are versioned so public builds work without
an external binary download. Never load or commit an untrusted model artifact.

## Build the explanation and prevention policy

After training the baseline models, build the validation-only sigmoid calibrators,
versioned advisory policy, explanation examples, and evaluation report:

```bash
python scripts/build_detection_policy.py
```

The generated policy maps calibrated risk scores to `allow`, `warn`, `quarantine`,
or `block` recommendations. For URL analysis, hostname and path/query text are
modeled separately so a brand name in an attacker's path is not confused with the
actual destination. A transparent exact-host safeguard based on pinned Tranco
top-domain data reduces false positives for popular HTTPS domains without trusting
lookalikes. Inputs without a scheme are analyzed as HTTPS and clearly disclosed.
These actions are advisory and are not enforced.

Unknown URL domains without concrete phishing evidence are labeled `unverified`
instead of being declared phishing from statistical similarity alone. This is the
expected offline behavior; live reputation is outside the current privacy boundary.

For email analysis, Policy 2.1 prevents an `allow` result when deterministic
checks find a reviewed combination of corroborating warning signs, such as urgent
language plus a credential request. This conservative floor produces
`suspicious/warn`, not an unsupported phishing declaration, and leaves the model's
calibrated probability visible separately.

## Production security controls

- Analysis requests are limited per network peer and return `429` with retry guidance.
- Inference is time-bounded and returns a controlled `504` response on timeout.
- Request bodies and schema fields are bounded independently.
- Explicit allowed hosts, restrictive browser headers, production HSTS, and
  no-store analysis responses reduce common web exposure.
- `requirements.lock` pins production dependencies with package hashes; CI audits
  the lock file for published vulnerabilities.
- GitHub Actions are pinned to immutable commits, while Dependabot and CodeQL
  monitor dependencies and source code.
- CI and container builds load the four packaged model artifacts only after their
  recorded sizes, SHA-256 digests, and runtime contracts are verified.
- A repeatable public smoke suite checks health, readiness, defensive headers,
  strict validation, a popular benign URL, and safe synthetic phishing fixtures.

These application limits protect a single process. A scaled or business-critical
deployment must add provider-level rate limiting and monitoring and configure its
hostname through `PHISHGUARD_ALLOWED_HOSTS`.

## Deploy the public demo

The root-level `render.yaml` defines a free Render Docker service with production
settings, an explicit host allowlist, deploys gated by passing GitHub checks, and
the artifact-aware `/ready` health check. The container binds to the hosting
platform's assigned `PORT` and retains port `8000` as its local default. Use the
**Deploy to Render** button above and follow the
[deployment guide](docs/deployment.md). Free services can have a cold start after
inactivity and are intended here for portfolio demonstration.

## Roadmap

- [x] Define project scope and threat model
- [x] Create the repository and development foundation
- [x] Build a reproducible data pipeline
- [x] Train and evaluate baseline email and URL models
- [x] Add calibration, explanations, and prevention policies
- [x] Expose the detector through a secure API
- [x] Build a responsive web dashboard
- [x] Test, harden, package, and deploy the system
- [ ] Compare the baseline with an advanced transformer or ensemble

## Current limitations

This repository now provides a responsive dashboard and offline email and URL
prediction endpoints with bounded inputs, verified artifacts, calibrated risk
scoring, explanations, an advisory response policy, packaged verified artifacts,
and a reproducible public Render deployment. The live release passed the versioned
smoke suite, but provider-level distributed rate limiting and durable external
monitoring are not included in the free demo. There are no administrative
endpoints; authentication will be required before adding any future administrative
capability.

## Responsible use

This project is intended for education, defensive security research, and
portfolio demonstration. It will not collect credentials, execute attachments,
visit submitted URLs, or claim to replace a layered email-security program.

## Contributing and security

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a
pull request. Report vulnerabilities according to [SECURITY.md](SECURITY.md), and do
not place active malicious URLs, credentials, or private messages in public issues.
