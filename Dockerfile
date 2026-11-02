FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONPATH=/app/src

# Scanner binaries moved to Dockerfile.sandbox (follow-up #1/#28).
# This image must NOT carry betterleaks/osv-scanner: the worker executes
# every tool in a fresh sandbox container, never in this image.

# git ships here for host-backend dev runs (SANDBOX_BACKEND=host, or auto
# outside prod): clones exec git directly in this image, and without it
# every GIT-repo scan and dependency check crashes with ENOENT. Prod is
# unaffected — the docker backend runs git in the sandbox image instead.
# Docker CLI from Docker's official repo, not Debian's docker.io: bookworm
# ships Docker 20.10 (API 1.41), which modern daemons reject outright
# ("client version 1.41 is too old, minimum supported API version is
# 1.44"). The worker shells out to this CLI for every sandbox run.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git gnupg postgresql-client \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/* \
    && docker --version && git --version

COPY pyproject.toml README.md ./
COPY src ./src
# Editable install: code under /app/src stays live so Compose watch sync works.
RUN uv sync --no-dev --editable

COPY . .

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "security_agent.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
