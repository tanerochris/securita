"""user_time filter: UTC instants into localizable <time> elements."""

from datetime import UTC, datetime, timedelta, timezone

from security_agent.app.timefmt import user_time


def test_naive_means_utc():
    out = str(user_time(datetime(2026, 11, 2, 15, 24, 38)))
    assert 'datetime="2026-11-02T15:24:38+00:00"' in out
    assert "2026-11-02 15:24 UTC" in out
    assert 'data-kind="datetime"' in out


def test_aware_converts_to_utc():
    plus2 = timezone(timedelta(hours=2))
    out = str(user_time(datetime(2026, 11, 2, 15, 24, 38, tzinfo=plus2)))
    assert 'datetime="2026-11-02T13:24:38+00:00"' in out


def test_already_utc_untouched():
    out = str(user_time(datetime(2026, 11, 2, 15, 24, 38, tzinfo=UTC)))
    assert 'datetime="2026-11-02T15:24:38+00:00"' in out


def test_none_renders_fallback():
    assert str(user_time(None)) == "—"
    assert str(user_time(None, "never")) == "never"


def test_date_kind():
    out = str(user_time(datetime(2026, 11, 2, 15, 24, 38), "undated", "date"))
    assert 'data-kind="date"' in out
    assert ">2026-11-02<" in out


def test_unknown_kind_falls_back_to_datetime():
    out = str(user_time(datetime(2026, 11, 2, 15, 24, 38), "—", "bogus"))
    assert 'data-kind="datetime"' in out


def test_strings_pass_through_escaped():
    assert str(user_time("2026-01-01")) == "2026-01-01"
    assert str(user_time(None, "<b>")) == "&lt;b&gt;"
