"""H5 Slice B: Betterleaks adapter — invocation, parse, caps, no-store."""

import json
from pathlib import Path
from unittest import mock

import pytest

from security_agent.sandbox import tools
from security_agent.worker import secrets as secrets_mod
from security_agent.worker.secrets import SecretError, liveness_of, normalize_report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _report(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_normalize_fs_report_yields_canonical_drafts():
    drafts, config_hash, dropped = normalize_report(_report("betterleaks-fs.json"))
    assert dropped == 0
    assert config_hash == "cfg-001"
    assert [(d["rule_id"], d["path"], d["liveness"]) for d in drafts] == [
        ("github-pat", ".env", "live"),
        ("aws-access-key", "config/settings.py", "dead"),
        ("generic-api-key", "notes.txt", "unknown"),
    ]
    assert drafts[0]["start_line"] == 3
    assert drafts[2]["start_line"] is None
    assert drafts[0]["commit_sha"] is None


def test_normalize_git_report_keeps_commit_sha():
    drafts, _, _ = normalize_report(_report("betterleaks-git.json"))
    assert drafts[0]["commit_sha"] == "abc123def456"
    assert drafts[0]["liveness"] == "live"
    assert drafts[1]["liveness"] == "dead"


def test_drafts_never_carry_secret_bytes():
    raw = (FIXTURES / "betterleaks-fs.json").read_text()
    report = json.loads(raw)
    secret_values = [f["match"]["value"] for f in report["findings"]]
    assert all(secret_values)
    drafts, _, _ = normalize_report(report)
    blob = repr(drafts)
    for value in secret_values:
        assert value not in blob


def test_malformed_entries_drop_loud_by_count():
    report = {
        "findings": [
            {"rule_id": "x", "match": {}, "location": {}},  # no path/fingerprint
            {"rule_id": "", "match": {"fingerprint": "z" * 64}, "location": {"path": "a"}},
            {"rule_id": "ok", "match": {"fingerprint": "ab" * 32}, "location": {"path": "a"}},
            "not-a-dict",
        ],
        "scan": {"state": "complete"},
    }
    drafts, _, dropped = normalize_report(report)
    assert [d["rule_id"] for d in drafts] == ["ok"]
    assert dropped == 3


def test_liveness_mapping():
    assert liveness_of("valid") == "live"
    assert liveness_of("invalid") == "dead"
    assert liveness_of("revoked") == "dead"
    assert liveness_of("needs_validation") == "unknown"
    assert liveness_of("unknown") == "unknown"
    assert liveness_of("error") == "unknown"
    assert liveness_of(None) == "unknown"
    assert liveness_of("bogus") == "unknown"


def test_incomplete_or_invalid_reports_fail_loud(tmp_path):
    with mock.patch.object(
        secrets_mod, "run_allowlisted", return_value=json.dumps({"findings": []})
    ):
        assert secrets_mod.scan_worktree(tmp_path)["findings"] == []
    with mock.patch.object(
        secrets_mod, "run_allowlisted", return_value=json.dumps({"findings": [], "scan": {}})
    ):
        secrets_mod.scan_worktree(tmp_path)  # missing state defaults to complete
    bad = json.dumps({"findings": [], "scan": {"state": "incomplete"}})
    with mock.patch.object(secrets_mod, "run_allowlisted", return_value=bad):
        with pytest.raises(SecretError, match="incomplete"):
            secrets_mod.scan_worktree(tmp_path)
    with mock.patch.object(secrets_mod, "run_allowlisted", return_value="not json"):
        with pytest.raises(SecretError, match="invalid JSON"):
            secrets_mod.scan_history(tmp_path)
    with mock.patch.object(secrets_mod, "run_allowlisted", return_value="[]"):
        with pytest.raises(SecretError, match="non-report"):
            secrets_mod.scan_worktree(tmp_path)


def test_invocation_argv_and_config(tmp_path, monkeypatch):
    seen: dict = {}

    def fake(name, args, **kwargs):
        seen["argv"] = args
        return json.dumps({"findings": [], "scan": {"state": "complete"}})

    monkeypatch.setattr(secrets_mod, "run_allowlisted", fake)
    secrets_mod.scan_worktree(tmp_path)
    assert seen["argv"][:4] == ["fs", str(tmp_path), "--validate", "--output"]
    assert "--config" not in seen["argv"]
    secrets_mod.scan_history(tmp_path)
    assert seen["argv"][:2] == ["git", str(tmp_path)]
    monkeypatch.setenv("SECRETS_CONFIG_PATH", "/etc/agent/secrets.toml")
    from security_agent import config as config_mod

    monkeypatch.setattr(config_mod, "_settings", None)
    secrets_mod.scan_worktree(tmp_path)
    assert "--config" in seen["argv"]
    monkeypatch.setattr(config_mod, "_settings", None)


def test_manifest_prefix_is_bare_binary():
    assert tools.MANIFEST["betterleaks"] == ["betterleaks"]


def test_scan_diff_blob_reports_rule_ids_only():
    canned = json.dumps(
        {
            "findings": [
                {"rule_id": "github-pat", "match": {"value": "ghp_SUPERSECRET"}},
                {"rule_id": "github-pat"},
                {"nope": True},
            ],
            "scan": {"state": "complete"},
        }
    )
    with mock.patch.object(secrets_mod, "run_allowlisted", return_value=canned) as run:
        assert secrets_mod.scan_diff_blob("+ghp_SUPERSECRET") == ["github-pat"]
        _, kwargs = run.call_args
        assert kwargs["stdin_data"] == "+ghp_SUPERSECRET"
        assert "--validate" not in run.call_args[0][1]  # detection only


def _fake_binary(path: Path) -> None:
    hit = '{"findings":[{"rule_id":"fake-rule"}],"scan":{"state":"complete"}}'
    miss = '{"findings":[],"scan":{"state":"complete"}}'
    script = path / "betterleaks"
    script.write_text(
        "#!/bin/sh\n"
        "body=$(cat)\n"
        'case "$body" in\n'
        f"  *FAKEMARKER*) printf '%s' '{hit}';;\n"
        f"  *) printf '%s' '{miss}';;\n"
        "esac\n"
    )
    script.chmod(0o755)


def test_scan_diff_blob_end_to_end_with_fake_binary(tmp_path, monkeypatch):
    import os

    _fake_binary(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    assert secrets_mod.betterleaks_available() is True
    assert secrets_mod.scan_diff_blob("+token FAKEMARKER here") == ["fake-rule"]
    assert secrets_mod.scan_diff_blob("+nothing interesting") == []


def test_diff_secret_violations_engine_and_marker_fallback(monkeypatch):
    from security_agent.worker import patch as patch_mod

    assert patch_mod.diff_secret_violations("+clean bump") == []
    monkeypatch.setattr(secrets_mod, "betterleaks_available", lambda: False)
    assert patch_mod.diff_secret_violations("+AKIAIOSFODNN7EXAMPLE") != []
    monkeypatch.setattr(secrets_mod, "betterleaks_available", lambda: True)
    monkeypatch.setattr(secrets_mod, "scan_diff_blob", lambda _b: ["fake-rule"])
    violations = patch_mod.diff_secret_violations("+clean bump")
    assert any("rule:fake-rule" in v for v in violations)

    def boom(_blob):
        raise SecretError("engine down")

    monkeypatch.setattr(secrets_mod, "scan_diff_blob", boom)
    assert patch_mod.diff_secret_violations("+clean bump") == []
    assert patch_mod.diff_secret_violations("+xoxb-fake") != []  # markers survive
