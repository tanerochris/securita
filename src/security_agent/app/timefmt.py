"""User-timezone date rendering: UTC storage in, local display out.

Every datetime is stored UTC (see models._utcnow). Templates must never
print a datetime raw; they use the `user_time` filter, which emits a
`<time>` element carrying the UTC instant. A script in base.html rewrites
the text via Intl.DateTimeFormat, so each reader sees their own timezone
and locale. Without JS, the server-rendered UTC text (explicitly
labeled) remains correct.
"""

from datetime import UTC, datetime

from markupsafe import Markup, escape


def _as_utc(value: datetime) -> datetime:
    """Naive (SQLite reads) means UTC; aware values convert to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def user_time(value: object, fallback: str = "—", kind: str = "datetime") -> Markup:
    """Render a datetime as a localizable <time> element.

    kind="datetime" shows date + time; kind="date" shows the calendar
    date only. None renders `fallback`; non-datetime values pass
    through escaped.
    """
    if value is None:
        return escape(fallback)
    if not isinstance(value, datetime):
        return escape(str(value))
    if kind not in ("datetime", "date"):
        kind = "datetime"
    utc = _as_utc(value)
    iso = utc.isoformat()
    text = utc.strftime("%Y-%m-%d") if kind == "date" else utc.strftime("%Y-%m-%d %H:%M UTC")
    # Safe: only isoformat/strftime output and an allowlisted kind are
    # interpolated; the fallback branch above is escaped.
    return Markup(  # noqa: S704
        f'<time datetime="{iso}" data-kind="{kind}" title="{iso}">{text}</time>'
    )
