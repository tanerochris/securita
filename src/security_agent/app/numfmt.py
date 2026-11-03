"""Human-readable number rendering: raw counts in, compact display out.

Large counts (notably token usage) are unreadable as plain digits, so
templates must never print a count raw; they use the `compact` filter,
which emits a `<span>` carrying the raw value in `data-num`. A script
in base.html rewrites the text via Intl.NumberFormat, so each reader
sees their own locale's separators. Without JS, the server-rendered
text remains correct, and `title` always holds the exact value.

kind="compact" (default) abbreviates with K/M/B/T; kind="grouped"
keeps full digits with thousands separators, which preserves the
Intl.Collator numeric ordering of sortable table columns.
"""

import math

from markupsafe import Markup, escape

_UNITS = (
    (1_000_000_000_000, "T"),
    (1_000_000_000, "B"),
    (1_000_000, "M"),
    (1_000, "K"),
)


def _short(number: float) -> str:
    """Compact en-style fallback: 999, 1K, 278.5K, 1.6M."""
    if abs(number) < 1000:
        return str(int(number)) if number.is_integer() else f"{number:g}"
    for i, (unit, suffix) in enumerate(_UNITS):
        if abs(number) >= unit:
            scaled = round(number / unit, 1)
            if abs(scaled) >= 1000 and i > 0:
                # Rounding overflow (999950 -> "1000K"): use the next unit up.
                scaled = round(number / _UNITS[i - 1][0], 1)
                suffix = _UNITS[i - 1][1]
            text = f"{scaled:.1f}"
            text = text[:-2] if text.endswith(".0") else text
            return f"{text}{suffix}"
    raise AssertionError("unreachable: magnitude >= 1000 always matches K")


def compact(value: object, fallback: str = "—", kind: str = "compact") -> Markup:
    """Render a count as a localizable compact/grouped `<span>`.

    None renders `fallback`; non-numeric values pass through escaped.
    """
    if value is None:
        return escape(fallback)
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return escape(str(value))
    if not math.isfinite(number):
        return escape(str(value))
    if kind not in ("compact", "grouped"):
        kind = "compact"
    whole = number.is_integer()
    raw = str(int(number)) if whole else repr(number)
    exact = f"{int(number):,}" if whole else f"{number:g}"
    text = exact if kind == "grouped" else _short(number)
    # Safe: raw/exact/text derive from the parsed float only (digits,
    # separators, K/M/B/T); every other branch above is escaped.
    return Markup(  # noqa: S704
        f'<span data-num="{raw}" data-kind="{kind}" title="{exact}">{text}</span>'
    )
