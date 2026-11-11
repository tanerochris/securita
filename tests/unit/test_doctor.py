"""Doctor preflight + sqlite-by-default config."""

from unittest import mock

import pytest

from security_agent.config import Settings
from security_agent.ops import doctor


def test_database_url_defaults_to_sqlite():
    default = Settings.model_fields["database_url"].default
    assert default.startswith("sqlite:///")


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_database_url_means_sqlite_default(monkeypatch, blank):
    """A blank `DATABASE_URL` must behave as unset (sqlite default)."""
    monkeypatch.setenv("DATABASE_URL", blank)
    assert Settings().database_url == Settings.model_fields["database_url"].default


def test_checks_cover_core_and_optional():
    checks = {c.name: c for c in doctor.run_checks()}
    for name in ("python", "database", "git", "ripgrep", "osv-scanner", "betterleaks"):
        assert checks[name].required is True
    assert checks["brain"].required is False
    assert checks["node"].required is False


def test_database_check_passes_on_test_db():
    checks = {c.name: c for c in doctor.run_checks()}
    assert checks["database"].ok is True
    assert "sqlite" in checks["database"].detail


def test_missing_binary_fails_its_check():
    real_which = doctor.shutil.which
    with mock.patch.object(
        doctor.shutil, "which", side_effect=lambda b: None if b == "git" else real_which(b)
    ):
        checks = {c.name: c for c in doctor.run_checks()}
    assert checks["git"].ok is False
    assert checks["git"].hint != ""


def test_main_exit_code_follows_required_checks(capsys):
    ok = [doctor.Check("python", True, "3.12", True, "")]
    with mock.patch.object(doctor, "run_checks", return_value=ok):
        assert doctor.doctor_main() is None  # success returns; exit 0 implied

    bad = [doctor.Check("git", False, "not found", True, "install git")]
    with mock.patch.object(doctor, "run_checks", return_value=bad):
        with pytest.raises(SystemExit) as exc:
            doctor.doctor_main()
    assert exc.value.code == 1
    assert "git" in capsys.readouterr().out
