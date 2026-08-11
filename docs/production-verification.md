# Production verification report

## Release under test

| Item | Verified value |
| --- | --- |
| Date | August 11, 2026 |
| Public service | `https://phishguard-ai-prototin.onrender.com/` |
| Git commit | `67f70463e87ffa81fa2d5df9feba2e611a006530` |
| Application version | `0.5.0` |
| Detection policy | `2.1.0` |
| Runtime | Render free Docker web service, production environment |

## Pre-deployment evidence

- All four model artifacts passed size, SHA-256, version, and load-contract checks.
- Ruff lint and formatting checks passed.
- Strict mypy type checking passed.
- All 88 automated tests passed with 92.49 percent statement/branch coverage,
  exceeding the 90 percent project gate.
- GitHub quality and CodeQL checks passed before the protected squash merge.
- The digest-pinned, non-root production image built successfully.
- Exact-container inference returned:
  - `youtube.com`: `legitimate`, 20, `allow`
  - reserved TEST-NET deceptive URL: `phishing`, 100, `block`
  - corroborated synthetic email: `suspicious`, 30, `warn`

## Live smoke-test evidence

The repeatable command below was executed after Render marked commit `67f7046`
live and the `/ready` deployment gate passed:

```bash
python scripts/smoke_test_deployment.py
```

Observed results:

| Check | Result |
| --- | --- |
| Dashboard over HTTPS | Pass |
| `/health` production response | `healthy` |
| `/ready` verified models | email and URL, Policy `2.1.0` |
| Popular benign URL regression | `legitimate`, 20 |
| Reserved deceptive URL regression | `phishing`, 100 |
| Corroborated deceptive email regression | `suspicious`, 30 |
| `Cache-Control: no-store` on analysis | Pass |
| CSP, HSTS, MIME and framing headers | Pass |
| Extra-field rejection | HTTP `422` |
| Full submitted fixture echo | Not present |

The fixtures are public and synthetic. The URL detector processed their text
offline and did not resolve or visit the submitted addresses.

## Finding resolved during verification

The first live verification found that a synthetic credential-theft email received
a low model probability and an `allow` result even though deterministic checks
identified urgency and a credential request. The result was not hidden or accepted.

Policy 2.1 now applies a conservative minimum score of 30 when a reviewed pair of
email warning signs corroborates one another. This changes the contradictory result
to `suspicious/warn`, not `phishing`, and keeps the original calibrated probability
visible. A single warning sign does not trigger the floor. Regression tests cover
both behaviors, and the model card documents the potential for legitimate security
notifications to receive a warning.

## Residual limitations

- This is an offline lexical baseline, not live URL reputation or page inspection.
- False positives and false negatives remain possible; results are advisory.
- The free Render service can cold-start after inactivity and does not provide
  enterprise availability.
- Rate limiting is process-local rather than distributed at the edge.
- The external email test is small and shows meaningful dataset shift.
- The service does not analyze sender authentication, attachments, images, QR
  codes, DNS history, certificates, or page behavior.

These limitations are intentionally visible in the README, model card, deployment
guide, and interface rather than being presented as production-grade certainty.
