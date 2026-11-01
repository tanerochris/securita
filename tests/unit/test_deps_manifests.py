"""Dependency manifests: discovery, D22 boundaries, lockfile resolution (D3/D12/D18)."""

import json
from pathlib import Path

from security_agent.worker import deps_manifests as dm


def _npm_root(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"left-pad": "^1.3.0", "exact": "2.0.0"},
                "optionalDependencies": {"fsevents": "~2.3.0"},
                "devDependencies": {"jest": "^29.0.0"},
                "peerDependencies": {"react": ">=18"},
            }
        )
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {},
                    "node_modules/left-pad": {"version": "1.3.0"},
                    "node_modules/exact": {"version": "2.0.0"},
                    "node_modules/left-pad/node_modules/nested": {"version": "9.9.9"},
                }
            }
        )
    )
    return tmp_path


def test_npm_tracks_prod_and_optional_not_dev(tmp_path):
    manifests, truncated = dm.discover_dep_manifests(_npm_root(tmp_path))
    assert not truncated
    assert len(manifests) == 1
    manifest = manifests[0]
    assert manifest.ecosystem == "npm" and manifest.lock_kind == "package-lock"
    by_name = {p.name: p for p in manifest.packages}
    assert set(by_name) == {"left-pad", "exact", "fsevents"}
    assert by_name["fsevents"].section == "optional"
    assert by_name["left-pad"].spec == "^1.3.0"
    assert manifest.peer_ranges == {"react": ">=18"}
    assert dm.installed_for(manifest, "left-pad") == "1.3.0"
    assert dm.installed_for(manifest, "exact") == "2.0.0"
    assert dm.installed_for(manifest, "fsevents") is None  # not in lock
    assert dm.installed_for(manifest, "nested") is None  # transitive: not tracked


def test_walk_skips_venvs_node_modules_and_vcs(tmp_path):
    _npm_root(tmp_path)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text('{"dependencies": {"evil": "1"}}')
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyproject.toml").write_text('[project]\ndependencies=["evil"]\n')
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "package.json").write_text('{"dependencies": {"evil": "1"}}')
    manifests, _ = dm.discover_dep_manifests(tmp_path)
    assert [m.rel for m in manifests] == ["package.json"]


def test_walk_finds_monorepo_manifests_and_caps(tmp_path):
    for i in range(dm.MAX_DEP_MANIFESTS + 5):
        sub = tmp_path / f"svc-{i:02d}"
        sub.mkdir()
        (sub / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}')
    manifests, truncated = dm.discover_dep_manifests(tmp_path)
    assert truncated  # never silent: callers note the cap on the tab
    assert len(manifests) == dm.MAX_DEP_MANIFESTS


def test_yarn_and_pnpm_locks_resolve(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "^1.0.0"}}')
    (tmp_path / "yarn.lock").write_text(
        'a@^1.0.0:\n  version "1.2.3"\n  resolved "https://x"\n'
    )
    manifest = dm._load_package_json(tmp_path / "package.json", "package.json")
    assert manifest.lock_kind == "yarn"
    assert dm.resolve_npm_lock(manifest) == {"a": "1.2.3"}
    (tmp_path / "yarn.lock").unlink()
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\npackages:\n  /a@1.4.0:\n    resolution: {tarball: x}\n"
        "  /@scope/b@2.0.1:\n    resolution: {tarball: y}\n"
    )
    manifest = dm._load_package_json(tmp_path / "package.json", "package.json")
    assert manifest.lock_kind == "pnpm"
    assert dm.resolve_npm_lock(manifest) == {"a": "1.4.0", "@scope/b": "2.0.1"}


def test_pyproject_pep621_and_extras_tracked_dev_groups_excluded(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'dependencies = ["requests>=2.0", "flask==3.0.0"]\n'
        "[project.optional-dependencies]\n"
        'web = ["gunicorn==21.0.0"]\n'
        "[dependency-groups]\n"
        'dev = ["pytest==8.0.0"]\n'
    )
    manifest = dm._load_pyproject(tmp_path / "pyproject.toml", "pyproject.toml")
    by_name = {p.name: p for p in manifest.packages}
    assert set(by_name) == {"requests", "flask", "gunicorn"}
    assert by_name["gunicorn"].section == "extra:web"
    assert by_name["requests"].spec == ">=2.0"


def test_pyproject_poetry_dev_group_excluded(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.dependencies]\n"
        'python = "^3.12"\n'
        'celery = "^5.3"\n'
        "[tool.poetry.group.dev.dependencies]\n"
        'pytest = "^8.0"\n'
        "[tool.poetry.group.docs.dependencies]\n"
        'sphinx = "^7.0"\n'
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "celery"\nversion = "5.3.1"\n'
        '[[package]]\nname = "sphinx"\nversion = "7.2.0"\n'
    )
    manifest = dm._load_pyproject(tmp_path / "pyproject.toml", "pyproject.toml")
    assert {p.name for p in manifest.packages} == {"celery", "sphinx"}
    assert manifest.lock_kind == "poetry"
    assert dm.installed_for(manifest, "celery") == "5.3.1"


def test_requirements_includes_and_dev_exclusion(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==4.2.0\n-r more.txt\n")
    (tmp_path / "more.txt").write_text("celery==5.3.0\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest==8.0.0\n")
    manifest = dm._load_requirements(tmp_path / "requirements.txt", "requirements.txt", tmp_path)
    assert {p.name for p in manifest.packages} == {"django", "celery"}
    assert dm.installed_for(manifest, "celery") == "5.3.0"
    dev = dm._load_requirements(
        tmp_path / "requirements-dev.txt", "requirements-dev.txt", tmp_path
    )
    assert dev.packages == []


def test_pipfile_packages_not_develop(tmp_path):
    (tmp_path / "Pipfile").write_text(
        '[packages]\ncelery = "==5.3.0"\n[dev-packages]\npytest = "*"\n'
    )
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({"default": {"celery": {"version": "==5.3.1"}}})
    )
    manifest = dm._load_pipfile(tmp_path / "Pipfile", "Pipfile")
    assert [(p.name, p.spec) for p in manifest.packages] == [("celery", "==5.3.0")]
    assert manifest.lock_kind == "pipfile"
    assert dm.installed_for(manifest, "celery") == "5.3.1"


def test_spec_exact_helpers():
    assert dm.npm_spec_exact("1.2.3") == "1.2.3"
    assert dm.npm_spec_exact("=1.2.3") == "1.2.3"
    assert dm.npm_spec_exact("^1.2.3") is None
    assert dm.npm_spec_exact("https://x.tgz") is None
    assert dm.pip_spec_exact("==1.2.3") == "1.2.3"
    assert dm.pip_spec_exact(">=1.0") is None
