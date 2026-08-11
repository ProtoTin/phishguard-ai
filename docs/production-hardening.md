# Production Hardening

## Phase 7 audit outcome

The local quality suite passes linting, formatting, strict typing, 79 automated
tests, and the 90 percent coverage gate. The project also builds a Python wheel.
The Phase 7 audit identified public-request abuse, long-running inference,
dependency drift, CI supply-chain risk, and model-artifact delivery as the main
deployment concerns.

## Implemented controls

- Analysis endpoints have a configurable per-peer, process-local rate limit.
- Model inference runs off the event loop with a configurable response deadline.
- Request-body and schema-level size limits remain enforced.
- Explicit host allowlisting rejects unexpected `Host` headers.
- Production responses add HSTS; all responses add defensive cross-origin,
  framing, MIME-sniffing, referrer, and permissions headers.
- Analysis results and controlled errors use `Cache-Control: no-store`.
- Production dependencies are version- and hash-pinned in `requirements.lock`.
- CI audits the production lock and pins third-party Actions to immutable commits.
- CodeQL scans Python changes and the default branch on a weekly schedule.
- GitHub secret scanning, push protection, Dependabot alerts, and automatic
  security update pull requests are enabled.
- The container runs as a non-root user, uses a read-only filesystem under
  Compose, pins its base-image digest, and removes `pip` and `setuptools` from
  the runtime image.

## Deployment requirements

Set `PHISHGUARD_ALLOWED_HOSTS` to the exact public hostname. Keep TLS termination
enabled and add provider-level request throttling, because the included rate
limiter is intentionally local to one process. Monitor `/health` for liveness and
`/ready` for verified model availability without sending private analysis input
to logs or third-party telemetry.

The four trusted Joblib model artifacts total less than 10 MB and are versioned
directly with the repository. This keeps public builds deterministic without Git
LFS or unauthenticated release downloads. CI and the runtime verify their recorded
sizes, SHA-256 digests, project-policy version, and load contract. Future generated
artifacts remain ignored unless they are deliberately reviewed and allowlisted.

## Residual risks

Timeout responses cannot forcibly stop Python code already executing in a worker
thread, although bounded inputs and rate limiting constrain exposure. A scaled
deployment requires a shared edge limit. Joblib remains pickle-based, so only
project-generated artifacts whose recorded digests match may be loaded. The
research models may still produce false positives and false negatives and remain
advisory rather than an automated security control.

Docker Scout reports two critical and two high findings in Debian's inherited
`perl` package, with no fixed Debian version available at the time of this audit.
PhishGuard does not invoke Perl, runs as an unprivileged user with no-new-privileges,
and uses a read-only filesystem under Compose, which reduces—but does not remove—the
base-image risk. Alpine was evaluated but rejected because scikit-learn 1.9 does not
publish a compatible musllinux wheel and would require a larger compiler toolchain.
Dependabot monitors the pinned base image so a fixed upstream digest can be adopted.
