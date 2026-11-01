"""Regression: default `up --build` must produce the sandbox image.

The sandbox-runner service was once behind `profiles: ["sandbox"]`, so a
plain deploy never built `security-agent-sandbox:latest` and every scan
died with the daemon's pull error ("repository does not exist or may
require 'docker login'").
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _runner_block() -> str:
    body = (ROOT / "compose.yaml").read_text()
    start = body.index("sandbox-runner:")
    # Block runs to the next top-level service or volumes section.
    rest = body[start:]
    for marker in ("\n  loki:", "\nvolumes:"):
        cut = rest.find(marker, 1)
        if cut != -1:
            rest = rest[:cut]
    return rest


def test_sandbox_runner_builds_on_default_up():
    assert "profiles:" not in _runner_block()


def test_sandbox_runner_tag_matches_worker_default():
    from security_agent.config import Settings

    assert f"image: {Settings().sandbox_image}" in _runner_block()


def test_work_volume_name_is_pinned():
    """The worker addresses the work volume by name; compose must not
    project-prefix it, or sibling mounts miss."""
    from security_agent.config import Settings

    body = (ROOT / "compose.yaml").read_text()
    assert f"name: {Settings().sandbox_work_volume}" in body
