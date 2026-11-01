"""Freshness: D13 latest selection, classification, native-tool parsing (D4)."""

import json

from security_agent.worker import deps_freshness as df


def test_classify_update():
    assert df.classify_update("1.2.3", "2.0.0") == "major"
    assert df.classify_update("1.2.3", "1.9.0") == "minor"
    assert df.classify_update("1.2.3", "1.2.9") == "patch"
    assert df.classify_update("1.2.3", "1.2.3") is None
    assert df.classify_update("1.2.3", "1.2.2") is None
    assert df.classify_update("1.2.3", "1.2.4rc1") == "patch"
    assert df.classify_update(None, "1.0.0") is None
    assert df.classify_update("not-a-version", "1.0.0") is None


def test_select_latest_stable_only_unless_installed_pre():
    versions = ["1.0.0", "2.0.0b1", "1.5.0"]
    assert df.select_latest(versions, "1.0.0") == "1.5.0"
    assert df.select_latest(versions, "2.0.0a1") == "2.0.0b1"
    assert df.select_latest(["1.0.0", "garbage"], "1.0.0") == "1.0.0"
    assert df.select_latest([], "1.0.0") is None


def test_parse_npm_outdated():
    out = json.dumps(
        {
            "left-pad": {"current": "1.3.0", "wanted": "1.9.0", "latest": "2.0.0"},
            "exact": {"current": "2.0.0", "wanted": "2.0.0", "latest": "2.0.0"},
        }
    )
    rows = df._parse_npm_outdated(out)
    assert rows["left-pad"] == {"current": "1.3.0", "wanted": "1.9.0", "latest": "2.0.0"}
    assert df._parse_npm_outdated("") == {}


def test_parse_yarn_classic_stream():
    out = (
        '{"type":"table","data":{"head":["Package","Current","Wanted","Latest"],'
        '"body":[["a","1.0.0","1.2.0","2.0.0"]]}}\n'
    )
    assert df._parse_yarn_outdated(out) == {
        "a": {"current": "1.0.0", "wanted": "1.2.0", "latest": "2.0.0"}
    }
    assert df._parse_yarn_outdated("not json at all") == {}


def _run_for(calls):
    def run(name, args, **kwargs):
        calls.append((name, args))
        if name == "npm" and args[:1] == ["outdated"]:
            return json.dumps({"a": {"current": "1.0.0", "wanted": "1.2.0", "latest": "2.0.0"}})
        if name == "npm" and args[:1] == ["view"]:
            return json.dumps("3.0.0")
        if name == "pip-index":
            return "a (1.0.0)\nAvailable versions: 2.0.0, 1.2.0, 1.0.0\n"
        raise AssertionError(f"unexpected tool call {name} {args}")

    return run


def test_check_npm_manifest_sweep_plus_latest(tmp_path):
    calls: list = []
    out = df.check_npm_manifest(
        tmp_path, {"a": ("1.0.0", "^1.0.0"), "b": ("2.0.0", "2.0.0")}, run=_run_for(calls)
    )
    assert out["a"].latest == "2.0.0" and out["a"].wanted == "1.2.0"
    assert out["a"].update_class == "major" and out["a"].error is None
    assert out["b"].latest == "3.0.0"  # sweep miss -> per-package view
    assert out["b"].update_class == "major"


def test_check_npm_manifest_names_tool_failure(tmp_path):
    def failing(name, args, **kwargs):
        raise RuntimeError("registry unreachable")

    out = df.check_npm_manifest(tmp_path, {"a": ("1.0.0", "^1.0.0")}, run=failing)
    assert out["a"].latest is None
    assert out["a"].error and "registry unreachable" in out["a"].error


def test_check_pip_packages_selects_stable():
    calls: list = []
    out = df.check_pip_packages({"a": ("1.0.0", "==1.0.0")}, run=_run_for(calls))
    assert out["a"].latest == "2.0.0"
    assert out["a"].update_class == "major"
    assert out["a"].wanted is None  # pip reports no in-range answer


def test_pip_available_versions_limited_parse():
    def run(name, args, **kwargs):
        return "a (1.0.0)\n  LATEST:    9.9.9\n"

    assert df.pip_available_versions("a", run=run) == ["9.9.9"]
