"""compact number filter: K/M/B fallback text plus localizable markup."""

import pytest

from security_agent.app.numfmt import compact


def _text(markup) -> str:
    return str(markup)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, ">0<"),
        (33, ">33<"),
        (999, ">999<"),
        (1000, ">1K<"),
        (1500, ">1.5K<"),
        (111495, ">111.5K<"),
        (278495, ">278.5K<"),
        (999949, ">999.9K<"),
        (999950, ">1M<"),
        (1604259, ">1.6M<"),
        (1594363, ">1.6M<"),
        (2000000000, ">2B<"),
        (1500000000000, ">1.5T<"),
        (-1500, ">-1.5K<"),
        ("1604259", ">1.6M<"),
    ],
)
def test_compact_short_text(value, expected):
    assert expected in _text(compact(value))


@pytest.mark.parametrize(
    ("value", "expected"),
    [(33, ">33<"), (1604259, ">1,604,259<"), (-278495, ">-278,495<")],
)
def test_compact_grouped_text(value, expected):
    assert expected in _text(compact(value, "—", "grouped"))


def test_compact_carries_raw_value_and_exact_title():
    out = _text(compact(1604259))
    assert 'data-num="1604259"' in out
    assert 'data-kind="compact"' in out
    assert 'title="1,604,259"' in out


def test_compact_grouped_marks_kind():
    assert 'data-kind="grouped"' in _text(compact(1604259, "—", "grouped"))


def test_compact_unknown_kind_falls_back_to_compact():
    out = _text(compact(1604259, "—", "bogus"))
    assert ">1.6M<" in out
    assert 'data-kind="compact"' in out


def test_compact_none_renders_fallback():
    assert _text(compact(None)) == "—"
    assert _text(compact(None, "n/a")) == "n/a"


def test_compact_non_numeric_passes_through_escaped():
    assert _text(compact("abc")) == "abc"
    assert _text(compact("<b>1</b>")) == "&lt;b&gt;1&lt;/b&gt;"
