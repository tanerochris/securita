"""Regression: worker/app image must ship a current Docker CLI.

Debian bookworm's `docker.io` is Docker 20.10 (API 1.41); modern daemons
reject it ("client version 1.41 is too old, minimum supported API version
is 1.44"), which fails every sandbox tool call. The image must install
docker-ce-cli from Docker's official repo instead.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _dockerfile() -> str:
    return (ROOT / "Dockerfile").read_text()


def test_worker_image_uses_official_docker_cli():
    body = _dockerfile()
    assert "docker-ce-cli" in body
    assert "download.docker.com" in body
    assert "docker --version" in body  # build-time smoke check


def test_worker_image_avoids_stale_debian_docker():
    for line in _dockerfile().splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "docker.io" not in stripped, line
