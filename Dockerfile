FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml requirements.lock README.md LICENSE ./
COPY src ./src
RUN python -m pip install --upgrade "pip==26.2.1" \
    && python -m pip wheel --require-hashes --wheel-dir /wheels \
        --requirement requirements.lock \
    && python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PHISHGUARD_ENVIRONMENT=production

RUN groupadd --system phishguard \
    && useradd --system --gid phishguard --create-home phishguard

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels "phishguard-ai[ml]==0.5.0" \
    && python -m pip uninstall --yes pip setuptools \
    && rm -rf /wheels

USER phishguard
WORKDIR /home/phishguard

COPY --chown=phishguard:phishguard config/detection-policy.json ./config/detection-policy.json
COPY --chown=phishguard:phishguard reports/model-evaluation.json ./reports/model-evaluation.json
COPY --chown=phishguard:phishguard artifacts ./artifacts

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.getenv('PORT', '8000')}/ready\", timeout=2)"]

CMD ["python", "-m", "phishguard.server"]
