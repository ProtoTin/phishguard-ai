# Analysis API Guide

## Purpose

PhishGuard 0.4.0 exposes calibrated email-text and URL analysis through FastAPI.
All submitted values are treated as untrusted plain text. URL analysis is fully
offline: the service does not resolve, retrieve, or visit the submitted address.
Results are advisory and may be incorrect.

The same endpoints power the dashboard at `/`; `/service` returns machine-readable
service information.

## Before starting

Reproduce the data, train the baseline models, and build the policy artifacts:

```bash
python scripts/download_data.py
python scripts/prepare_data.py
python scripts/train_models.py
python scripts/build_detection_policy.py
uvicorn phishguard.main:app --reload
```

`GET /health` reports process liveness. `GET /ready` verifies and loads the
recorded base and calibrated artifact hashes. Analysis returns `503` until that
verification succeeds.

## Analyze email text

```bash
curl --request POST http://localhost:8000/v1/analyze/email \
  --header "Content-Type: application/json" \
  --data '{"content":"Urgent: verify your account password immediately."}'
```

The `content` value must contain 1–50,000 characters. It can contain a subject,
body, or both as plain text; HTML is analyzed as text and is never rendered.

## Analyze a URL

```bash
curl --request POST http://localhost:8000/v1/analyze/url \
  --header "Content-Type: application/json" \
  --data '{"url":"http://192.0.2.10/login/verify-account/password"}'
```

The `url` value must contain 1–2,048 characters. The analysis uses only string
and parsed lexical properties.

## Response contract

A successful response contains:

- `classification`: `legitimate`, `suspicious`, or `phishing`
- `risk_score`: calibrated integer score from 0 to 100
- `recommended_action`: `allow`, `warn`, `quarantine`, or `block`
- controlled reasons and directly observed evidence
- supporting and mitigating linear-model features
- model and policy versions
- `advisory_only: true` and an explicit safety note

The response never includes the submitted email or URL. Analysis responses send
`Cache-Control: no-store`, and the application does not add submitted content to
its logs or persist it.

## Input and failure behavior

- The complete HTTP request body is limited to 65,536 bytes, including for
  chunked requests without a `Content-Length` header; oversized bodies return
  `413`.
- Empty, oversized-field, incorrectly typed, or extra fields return `422`.
- Missing, changed, or version-incompatible model artifacts return a generic
  `503` without exposing local paths or loader details.
- Artifact loading verifies the SHA-256 values in the versioned reports before
  invoking pickle-based Joblib deserialization. Only locally generated trusted
  artifacts should be used.

Authentication, deployment-level rate limits, and multi-worker processing
timeouts remain required before exposing the service publicly.
