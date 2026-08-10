# Contributing to PhishGuard

Thank you for improving this defensive security project. Contributions should keep
the system explainable, reproducible, privacy-conscious, and honest about uncertainty.

## Development workflow

1. Fork the repository and create a focused branch.
2. Follow the setup instructions in `README.md` and `docs/development.md`.
3. Add or update tests for every behavior change.
4. Run the complete quality suite before opening a pull request:

   ```bash
   ruff format --check .
   ruff check .
   mypy src tests
   pytest -q
   ```

5. Explain the security impact, evaluation evidence, and limitations in the pull
   request description.

## Safety and data rules

- Never commit credentials, API keys, private email, raw datasets, or trained model
  artifacts.
- Treat every URL as inert text. Do not visit or resolve dataset URLs during tests.
- Use reserved domains and IP ranges such as `.test`, `.example`, and `192.0.2.0/24`
  for synthetic examples.
- Do not weaken request limits, artifact verification, output escaping, or the
  uncertainty policy without documenting the security rationale.
- Do not describe an absent reputation match as proof that a URL is safe.

## Pull-request scope

Prefer small changes with reproducible evidence. Useful contributions include new
regression cases, evaluation methods, accessibility improvements, documented
threat-intelligence adapters, and security hardening.
