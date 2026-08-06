# Contributing

Thank you for helping improve PhishGuard. This project accepts defensive,
educational contributions that respect user privacy and the responsible-use
guidelines in the README.

## Development workflow

1. Create a focused branch from `main`.
2. Set up the environment using `docs/development.md`.
3. Add or update tests with the change.
4. Run linting, formatting, type checks, and tests locally.
5. Open a pull request describing the problem, solution, and validation.

Do not commit credentials, private email messages, downloaded datasets, or
generated model artifacts. Dataset additions must include provenance, license,
privacy, and label-quality documentation.

## Pull-request expectations

- Keep changes focused and explain security-relevant decisions.
- Preserve the rule that submitted URLs are not fetched by the analysis path.
- Treat all submitted email fields and model outputs as untrusted data.
- Report model changes with comparable metrics on an untouched test set.
- Update documentation when behavior, configuration, or limitations change.

Security vulnerabilities should follow `SECURITY.md` instead of a public issue.
