FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONPATH=/app/src

# Scanner binaries moved to Dockerfile.sandbox (follow-up #1/#28).
# This image must NOT carry betterleaks/osv-scanner: the worker executes
# every tool in a fresh sandbox container, never in this image.

RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
# Editable install: code under /app/src stays live so Compose watch sync works.
RUN uv sync --no-dev --editable

COPY . .

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "security_agent.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
