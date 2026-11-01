"""Impact reports: sections, summary fallback/outage, peer ranges (D6/D9/D22/D23)."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Dependency,
    DependencyReport,
    DependencyStatus,
    RepoKind,
)
from security_agent.db.session import session_scope
from security_agent.worker import deps_report as dr


def _dep(**overrides):
    base = {
        "ecosystem": "npm",
        "manifest_path": "package.json",
        "package": "left-pad",
        "section": "dependencies",
        "manifest_spec": "^1.3.0",
        "installed_version": "1.3.0",
        "wanted_version": "1.9.0",
        "latest_version": "2.0.0",
        "update_class": "major",
        "security": False,
    }
    base.update(overrides)
    return Dependency(**base)


def test_build_section_names_evidence_and_gaps():
    section = dr.build_section(
        _dep(),
        usage_sites=["index.js:1"],
        peer_ranges={"left-pad": "^1.0.0"},
        advisories=["CVE-X"],
    )
    assert section["key"] == "npm|package.json|left-pad"
    assert section["anchor"].startswith("pkg-")
    assert section["usage_sites"] == ["index.js:1"]
    assert "excludes latest" in section["peer_note"]  # D22 peer note
    assert "presumed breaking" in section["breaking_flag"]
    assert "in-range alternative 1.9.0" in section["wanted_note"]
    assert "UNDETERMINED" in section["changelog"]


def test_satisfies_npm_range():
    assert dr.satisfies_npm_range("^1.2.3", "1.9.0") is True
    assert dr.satisfies_npm_range("^1.2.3", "2.0.0") is False
    assert dr.satisfies_npm_range("~1.2.3", "1.2.9") is True
    assert dr.satisfies_npm_range("~1.2.3", "1.3.0") is False
    assert dr.satisfies_npm_range("1.2.3", "1.2.3") is True
    assert dr.satisfies_npm_range(">=1.0.0 <2.0.0", "1.9.0") is True
    assert dr.satisfies_npm_range("*", "9.9.9") is True
    assert dr.satisfies_npm_range("https://x.tgz", "1.0.0") is None
    assert dr.satisfies_npm_range("^1.0.0", "garbage") is None


def test_fallback_summary_is_deterministic():
    section = dr.build_section(_dep(), usage_sites=[])
    out = dr.fallback_summary([section])
    assert "left-pad 1.3.0 -> 2.0.0 (major)" in out
    assert "likely affected" in out and "UNDETERMINED" in out


def test_generate_summary_model_backed_and_outage():
    section = dr.build_section(_dep(), usage_sites=[])

    class _Ok:
        def invoke(self, prompt):
            assert "left-pad" in prompt  # evidence reaches the model
            return SimpleNamespace(content="model verdict", usage_metadata={})

    text, backed = dr.generate_summary([section], model=_Ok())
    assert (text, backed) == ("model verdict", True)

    class _Outage:
        def invoke(self, prompt):
            raise RuntimeError("boom")

    with pytest.raises(dr.ReportError):
        dr.generate_summary([section], model=_Outage())

    class _Empty:
        def invoke(self, prompt):
            return SimpleNamespace(content="  ", usage_metadata={})

    text, backed = dr.generate_summary([section], model=_Empty())
    assert backed is False and "template fallback" in text


def test_generate_summary_disabled_falls_back_without_call():
    from security_agent.config import Settings, get_settings

    declared = Settings.model_fields["deps_report_model_enabled"].default
    assert declared is True  # default on in prod
    assert get_settings().deps_report_model_enabled is False  # conftest hermetic default
    section = dr.build_section(_dep(), usage_sites=[])
    text, backed = dr.generate_summary([section])
    assert backed is False and "template fallback" in text


def test_create_report_moves_rows_and_supersedes():
    repo = repo_svc.connect_repo(
        f"deprep-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/x"
    )
    with session_scope() as db:
        db.add(
            Dependency(
                repo_id=repo.id, ecosystem="npm", manifest_path="package.json",
                package="a", installed_version="1.0.0", latest_version="2.0.0",
                status=DependencyStatus.UPDATE_AVAILABLE,
            )
        )
        db.add(
            DependencyReport(
                repo_id=repo.id, status="pending", summary="old", sections=[],
                undecided_keys=["npm|package.json|a"],
            )
        )
    section = dr.build_section(_dep(package="a", installed_version="1.0.0"))
    report = dr.create_report(repo.id, None, [section], "new", model_backed=True,
                              update_set_hash="h")
    assert report.status == "pending"
    assert report.undecided_keys == ["npm|package.json|a"]
    with session_scope() as db:
        from sqlalchemy import select

        rows = list(db.scalars(select(Dependency).where(Dependency.repo_id == repo.id)))
        assert rows[0].status == DependencyStatus.AWAITING_DECISION
        reports = list(
            db.scalars(select(DependencyReport).where(DependencyReport.repo_id == repo.id))
        )
        assert sorted(r.status for r in reports) == ["pending", "superseded"]
