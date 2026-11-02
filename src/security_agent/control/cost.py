"""Cost control: token ledger, per-run spend caps, park/resume, spend alerts (NFR-8).

Per-run spend cap (default $2.00) warns at 80% and hard-stops by
parking the run; parked runs resume only under a raised cap via an
Owner/Maintainer. Zero disables the cap. Daily spend alerts fire once
per level per day. `CostCapExceeded` inherits plain Exception
deliberately: the patch repair loop swallows (PatchError, ScanError,
RuntimeError, TimeoutError), and a parked run must abort, never retry.

Every model call in the app ledgers here (chat via `tracked_invoke`,
dependency summaries via `record_deps_usage`, embeddings via
`record_usage`), so `usage_summary` is the complete AI bill: total /
input / output tokens plus spend per day, week, and month. The
overall monthly spend cap is alert-only by design: warn at 80%,
exceeded at 100%, once per level per month; pipelines keep running.
"""

import logging
from contextvars import ContextVar, Token
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import case, delete, func, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError

from security_agent.audit import get_shared_log
from security_agent.config import get_settings
from security_agent.db.models import ModelUsage, NotifyState, Role, ScanRun, User
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)
audit = get_shared_log()

_run_id: ContextVar[int | None] = ContextVar("cost_run_id", default=None)

# Monthly-cap warn line as a fraction of the cap (alert-only, no parking).
_MONTHLY_WARN_FRACTION = 0.8
_SPEND_CAP_KEY = "cost.spend_cap_monthly"
_SPEND_CAP_ALERT_KEY = "cost.spend_cap_alert"
_RUN_CAP_KEY = "cost.run_cap_usd"
_RUN_CAP_LEGACY_KEY = "cost.run_cap"  # pre-USD token override, converted at price


class CostCapExceeded(Exception):
    """Per-run spend cap hit: the run is parked, abort the pipeline."""


class run_context:
    """Bind model usage in this block to a run for cap accounting."""

    def __init__(self, run_id: int | None) -> None:
        self.run_id = run_id
        self._token: Token[int | None] | None = None

    def __enter__(self) -> None:
        self._token = _run_id.set(self.run_id)

    def __exit__(self, *exc: object) -> None:
        if self._token is None:  # pragma: no cover - __enter__ always sets it
            return
        _run_id.reset(self._token)


def current_run_id() -> int | None:
    return _run_id.get()


def format_usd(amount: float) -> str:
    """$X.XX, widening to 4/6 decimals only while the amount rounds to $0.00."""
    value = float(amount or 0.0)
    if value == 0:
        return "$0.00"
    for places in (2, 4, 6):
        if round(abs(value), places):
            return f"${value:.{places}f}"
    return f"${value:.6f}"


def _run_cap_in_session(db) -> float:
    """Per-run spend cap in USD read inside an open session (no nested session)."""
    row = db.get(NotifyState, _RUN_CAP_KEY)
    if row is not None:
        try:
            return max(0.0, float(row.value))
        except ValueError:
            pass
    legacy = db.get(NotifyState, _RUN_CAP_LEGACY_KEY)
    if legacy is not None:
        try:
            return max(0.0, float(legacy.value)) * _price_per_token()
        except ValueError:
            pass
    return max(0.0, get_settings().run_cap_default_usd)


def effective_run_cap() -> float:
    """Per-run spend cap in USD: install override wins, else the env default.

    Zero disables the cap. A legacy pre-USD token override converts at
    the current model price until a USD cap replaces it.
    """
    with session_scope() as db:
        return _run_cap_in_session(db)


def _write_run_cap(db, value: float) -> None:
    """Persist the install-wide per-run cap; retires any legacy token override."""
    row = db.get(NotifyState, _RUN_CAP_KEY)
    if row is None:
        db.add(NotifyState(key=_RUN_CAP_KEY, value=str(value)))
    else:
        row.value = str(value)
    legacy = db.get(NotifyState, _RUN_CAP_LEGACY_KEY)
    if legacy is not None:
        db.delete(legacy)


def set_run_cap(value: float, user: User) -> float:
    """Owner/Maintainer sets the install-wide per-run spend cap (0 disables)."""
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may change cost caps.")
    if value < 0:
        raise ValueError("Cap must be at least 0 (0 disables the cap).")
    with session_scope() as db:
        _write_run_cap(db, value)
    audit.append(
        action_class="cost",
        decision="cap",
        line=f"cap_usd={value} by={user.id} role={user.role.value}",
    )
    return value


def _spend_cap_in_session(db) -> float:
    """Monthly spend cap read inside an open session (no nested session)."""
    row = db.get(NotifyState, _SPEND_CAP_KEY)
    if row is not None:
        try:
            return max(0.0, float(row.value))
        except ValueError:
            pass
    return max(0.0, get_settings().spend_cap_monthly_usd)


def effective_spend_cap() -> float:
    """Overall monthly spend cap in USD: install override wins, else env.

    Zero disables the cap (dashboard shows spend without a limit line,
    and no monthly-cap alerts fire).
    """
    with session_scope() as db:
        return _spend_cap_in_session(db)


def set_spend_cap(value: float, user: User) -> float:
    """Owner/Maintainer sets the overall monthly spend cap (0 disables)."""
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may change cost caps.")
    if value < 0:
        raise ValueError("Cap must be at least 0 (0 disables the cap).")
    with session_scope() as db:
        row = db.get(NotifyState, _SPEND_CAP_KEY)
        if row is None:
            db.add(NotifyState(key=_SPEND_CAP_KEY, value=str(value)))
        else:
            row.value = str(value)
    audit.append(
        action_class="cost",
        decision="spend-cap",
        line=f"cap={value} by={user.id} role={user.role.value}",
    )
    return value


def _price_per_token() -> float:
    return max(0.0, get_settings().model_price_per_mtok_usd) / 1_000_000


def _try_park_run(db, run_id: int, spent: float, cap: float) -> bool:
    """Guarded park flip; True only when this call flipped the flag."""
    park_msg = f"parked: spend cap hit ({format_usd(spent)} of {format_usd(cap)})"
    res = db.execute(
        update(ScanRun)
        .where(
            ScanRun.id == run_id,
            ScanRun.parked.is_(False),
            func.coalesce(ScanRun.cost_usd, 0.0) >= cap,
        )
        .values(
            parked=True,
            park_reason=f"spend cap hit: {format_usd(spent)} >= {format_usd(cap)}",
            notes=case(
                (or_(ScanRun.notes.is_(None), ScanRun.notes == ""), park_msg),
                else_=ScanRun.notes + "\n" + park_msg,
            ),
        )
    )
    return (cast("CursorResult[Any]", res).rowcount or 0) == 1


def _try_warn_run(db, run_id: int, warn_at: float) -> bool:
    """Guarded warn flip; True only when this call flipped the flag."""
    res = db.execute(
        update(ScanRun)
        .where(
            ScanRun.id == run_id,
            ScanRun.cost_warned.is_(False),
            ScanRun.parked.is_(False),
            func.coalesce(ScanRun.cost_usd, 0.0) >= warn_at,
        )
        .values(cost_warned=True)
    )
    return (cast("CursorResult[Any]", res).rowcount or 0) == 1


def record_usage(
    run_id: int | None,
    task: str,
    prompt_tokens: int,
    completion_tokens: int,
    *,
    estimated: bool = False,
) -> dict:
    """Ledger one model call; warn/park at the spend cap (run-bound calls only).

    ONE session, no nested sessions: the cap read, the ModelUsage
    insert, and the spend/token increments share a single transaction,
    and guarded flag updates (rowcount decides) keep concurrent
    callers to exactly one warn and one park. Spend alerts run for
    every call including run-less ones. Raises CostCapExceeded
    whenever this call finds spend at/over an enabled cap; alerts fire
    only when this call flipped the flag. A zero cap disables
    warn/park (usage still ledgers).
    """
    total = max(0, prompt_tokens) + max(0, completion_tokens)
    cost = total * _price_per_token()
    warned = parked = False
    spent = 0.0
    tokens = 0
    cap = 0.0
    run_found = False
    with session_scope() as db:
        cap = _run_cap_in_session(db)
        enabled = cap > 0
        warn_at = cap * get_settings().run_spend_warn_fraction
        db.add(
            ModelUsage(
                run_id=run_id,
                task=task[:100],
                prompt_tokens=max(0, prompt_tokens),
                completion_tokens=max(0, completion_tokens),
                total_tokens=total,
                cost_usd=cost,
                estimated=estimated,
            )
        )
        if run_id is not None:
            incremented = db.execute(
                update(ScanRun)
                .where(ScanRun.id == run_id)
                .values(
                    token_usage=func.coalesce(ScanRun.token_usage, 0) + total,
                    cost_usd=func.coalesce(ScanRun.cost_usd, 0.0) + cost,
                )
                .returning(ScanRun.cost_usd, ScanRun.token_usage)
            ).one_or_none()
            if incremented is not None:
                run_found = True
                spent = float(incremented[0] or 0.0)
                tokens = incremented[1] or 0
                if enabled and spent >= cap:
                    parked = _try_park_run(db, run_id, spent, cap)
                elif enabled and spent >= warn_at:
                    warned = _try_warn_run(db, run_id, warn_at)
    # Alerts fire after commit; the park abort raises past them.
    if warned:
        _alert_cost(
            "medium",
            f"run {run_id} at {format_usd(spent)} (cap {format_usd(cap)})",
            "warn",
            f"Run {run_id} passed 80% of its {format_usd(cap)} spend cap.",
        )
    if parked:
        _alert_cost(
            "high",
            f"run {run_id} parked at {format_usd(spent)}",
            "parked",
            f"Run {run_id} hit its {format_usd(cap)} spend cap and parked. "
            "Raise the cap and resume from the dashboard to continue.",
        )
    if run_found and enabled and spent >= cap:
        raise CostCapExceeded(f"run {run_id} parked: spend cap hit ({format_usd(spent)})")
    check_spend_alerts()
    check_monthly_cap_alerts()
    return {"total": total, "cost_usd": cost, "run_usage": tokens, "run_spend": spent}


def _alert_cost(severity: str, subject: str, kind: str, body: str) -> None:
    from security_agent.notify import notify_event

    notify_event(severity, f"cost {kind}: {subject}", body, link="/settings", kind=f"cost-{kind}")


def spend_today(now: datetime | None = None) -> float:
    """Sum of ledger cost since UTC midnight (SQL-side aggregate)."""
    now = now or datetime.now(UTC)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    with session_scope() as db:
        bind = db.get_bind()
        is_sqlite = bind is not None and bind.dialect.name == "sqlite"
        cutoff = day_start.replace(tzinfo=None) if is_sqlite else day_start
        total = db.scalar(
            select(func.coalesce(func.sum(ModelUsage.cost_usd), 0.0)).where(
                ModelUsage.created_at >= cutoff
            )
        )
        return float(total or 0.0)


def _usage_totals_since(db, cutoff: datetime) -> dict:
    """One SQL-side aggregate: input/output/total tokens + spend since cutoff."""
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "sqlite":
        cutoff = cutoff.replace(tzinfo=None)
    row = db.execute(
        select(
            func.coalesce(func.sum(ModelUsage.prompt_tokens), 0),
            func.coalesce(func.sum(ModelUsage.completion_tokens), 0),
            func.coalesce(func.sum(ModelUsage.total_tokens), 0),
            func.coalesce(func.sum(ModelUsage.cost_usd), 0.0),
        ).where(ModelUsage.created_at >= cutoff)
    ).one()
    return {
        "prompt_tokens": int(row[0] or 0),
        "completion_tokens": int(row[1] or 0),
        "total_tokens": int(row[2] or 0),
        "spend_usd": float(row[3] or 0.0),
    }


def usage_summary(now: datetime | None = None) -> dict:
    """Complete AI bill for the dashboard: day, week, and month windows.

    Day runs since UTC midnight, week is the rolling last 7 days, month
    is the calendar month (UTC). Every window sums the whole ModelUsage
    ledger — security pipeline, dependencies, embeddings, probe — as
    input / output / total tokens plus spend in USD.
    """
    now = now or datetime.now(UTC)
    cutoffs = {
        "day": now.replace(hour=0, minute=0, second=0, microsecond=0),
        "week": now - timedelta(days=7),
        "month": now.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
    }
    with session_scope() as db:
        return {name: _usage_totals_since(db, at) for name, at in cutoffs.items()}


def month_spend(now: datetime | None = None) -> float:
    """Sum of ledger cost since the first of the calendar month (UTC)."""
    now = now or datetime.now(UTC)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    with session_scope() as db:
        return _usage_totals_since(db, month_start)["spend_usd"]


def check_monthly_cap_alerts(now: datetime | None = None) -> dict:
    """Monthly-cap warn/exceeded alerts, once per level per calendar month.

    Alert-only: pipelines keep running past the cap. A zero cap means
    no cap: spend is reported, no level, never an alert.
    """
    now = now or datetime.now(UTC)
    spent = month_spend(now)
    cap = effective_spend_cap()
    if cap <= 0:
        return {"spent": spent, "cap": cap, "level": ""}
    level = ""
    if spent >= cap:
        level = "exceeded"
    elif spent >= cap * _MONTHLY_WARN_FRACTION:
        level = "warn"
    if not level:
        return {"spent": spent, "cap": cap, "level": ""}
    stamp = f"{now.strftime('%Y-%m')}:{level}"
    if not _claim_monthly_cap_stamp(level, stamp):
        return {"spent": spent, "cap": cap, "level": level, "alerted": False}
    _alert_cost(
        "high" if level == "exceeded" else "medium",
        f"monthly spend ${spent:.2f} ({level}, cap ${cap:.2f})",
        f"spend-cap-{level}",
        f"Model spend this month reached ${spent:.2f} ({level}; cap ${cap:.2f}). "
        "Raise the cap from the settings page.",
    )
    return {"spent": spent, "cap": cap, "level": level, "alerted": True}


def spend_cap_state(now: datetime | None = None) -> dict:
    """Monthly-cap dashboard state: spent, cap, pct, level. Fires no alerts.

    `level` is "" (under 80%), "warn", or "exceeded"; a zero cap means
    no cap (level always "", pct 0). Views use this; only ledger
    writes call `check_monthly_cap_alerts`.
    """
    now = now or datetime.now(UTC)
    spent = month_spend(now)
    cap = effective_spend_cap()
    level = ""
    if cap > 0:
        if spent >= cap:
            level = "exceeded"
        elif spent >= cap * _MONTHLY_WARN_FRACTION:
            level = "warn"
    return {
        "spent": spent,
        "cap": cap,
        "pct": round(100 * spent / cap) if cap > 0 else 0,
        "level": level,
    }


def _claim_monthly_cap_stamp(level: str, stamp: str) -> bool:
    """Atomically claim this month's cap-alert stamp; True iff this call won.

    Same guarded-UPDATE + INSERT-on-missing race cover as the daily
    spend stamps: an exceeded caller that loses to a concurrent warn
    stamp retries so warn->exceeded still escalates.
    """
    month = stamp.split(":", 1)[0]
    key = _SPEND_CAP_ALERT_KEY
    for _ in range(3):
        with session_scope() as db:
            if level == "exceeded":
                guard = NotifyState.value != f"{month}:exceeded"
            else:
                guard = NotifyState.value.notin_([f"{month}:warn", f"{month}:exceeded"])
            res = db.execute(
                update(NotifyState).where(NotifyState.key == key, guard).values(value=stamp)
            )
            if (cast("CursorResult[Any]", res).rowcount or 0) == 1:
                return True
            try:
                db.add(NotifyState(key=key, value=stamp))
                db.flush()
            except IntegrityError:
                db.rollback()
                row = db.get(NotifyState, key)
                stamped = row.value if row else ""
                if stamped == f"{month}:exceeded" or (
                    stamped == f"{month}:warn" and level == "warn"
                ):
                    return False
                continue  # Escalate, or the winner rolled back: retry the guard.
            else:
                return True
    return False


def check_spend_alerts(now: datetime | None = None) -> dict:
    """Daily warn/critical spend alerts, once per level per day."""
    now = now or datetime.now(UTC)
    settings = get_settings()
    spend = spend_today(now)
    level = ""
    if spend >= settings.spend_critical_daily_usd:
        level = "critical"
    elif spend >= settings.spend_warn_daily_usd:
        level = "warn"
    if not level:
        return {"spend": spend, "level": ""}
    stamp = f"{now.date().isoformat()}:{level}"
    if not _claim_spend_stamp(level, stamp):
        return {"spend": spend, "level": level, "alerted": False}
    _alert_cost(
        "high" if level == "critical" else "medium",
        f"daily spend ${spend:.2f} ({level})",
        f"spend-{level}",
        f"Model spend today reached ${spend:.2f} ({level} threshold).",
    )
    return {"spend": spend, "level": level, "alerted": True}


def _claim_spend_stamp(level: str, stamp: str) -> bool:
    """Atomically claim today's spend-alert stamp; True iff this call won.

    A guarded UPDATE (rowcount 1 wins) beats a concurrent claimer;
    INSERT-on-missing with IntegrityError meaning lost covers the
    no-row race. A critical caller that loses to a concurrent warn
    stamp retries so warn->critical still escalates.
    """
    today = stamp.split(":", 1)[0]
    key = "cost.spend_alert"
    for _ in range(3):
        with session_scope() as db:
            if level == "critical":
                guard = NotifyState.value != f"{today}:critical"
            else:
                guard = NotifyState.value.notin_([f"{today}:warn", f"{today}:critical"])
            res = db.execute(
                update(NotifyState).where(NotifyState.key == key, guard).values(value=stamp)
            )
            if (cast("CursorResult[Any]", res).rowcount or 0) == 1:
                return True
            try:
                db.add(NotifyState(key=key, value=stamp))
                db.flush()
            except IntegrityError:
                db.rollback()
                row = db.get(NotifyState, key)
                stamped = row.value if row else ""
                if stamped == f"{today}:critical" or (
                    stamped == f"{today}:warn" and level == "warn"
                ):
                    return False
                continue  # Escalate, or the winner rolled back: retry the guard.
            else:
                return True
    return False


def purge_old_usage(older_than_days: int = 90) -> int:
    """Delete ModelUsage rows older than the retention window; returns the count."""
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    with session_scope() as db:
        bind = db.get_bind()
        if bind is not None and bind.dialect.name == "sqlite":
            cutoff = cutoff.replace(tzinfo=None)
        res = db.execute(delete(ModelUsage).where(ModelUsage.created_at < cutoff))
        return int(cast("CursorResult[Any]", res).rowcount or 0)


def list_parked_runs() -> list[dict]:
    """Parked runs with repo names for the dashboard resume queue."""
    from security_agent.db.models import Repo

    with session_scope() as db:
        rows = list(
            db.scalars(select(ScanRun).where(ScanRun.parked.is_(True)).order_by(ScanRun.id))
        )
        out = []
        for run in rows:
            repo = db.get(Repo, run.repo_id)
            out.append(
                {
                    "id": run.id,
                    "repo_id": run.repo_id,
                    "repo_name": repo.name if repo else f"repo#{run.repo_id}",
                    "token_usage": run.token_usage or 0,
                    "spend_usd": float(run.cost_usd or 0.0),
                    "reason": run.park_reason or "",
                }
            )
            db.expunge(run)
        return out


def resume_run(run_id: int, user: User, *, new_cap: float | None = None) -> dict:
    """Unpark a run; resumes only under a raised cap (NFR-8 D5).

    When spend already covers the effective cap, `new_cap` (above
    spend) is required and becomes the install cap. Clears the claim
    so the next worker pass picks the run up; the pipeline re-runs
    from the top (scan/patch/deliver dedup keeps it safe). A disabled
    (zero) cap resumes without a raise.
    """
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may resume parked runs.")
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        if run is None:
            raise ValueError(f"Unknown run {run_id}.")
        if not run.parked:
            raise ValueError(f"Run {run_id} is not parked.")
        spent = float(run.cost_usd or 0.0)
        cap = effective_run_cap()
        if new_cap is not None:
            if new_cap <= spent:
                raise ValueError(
                    f"New cap {format_usd(new_cap)} must exceed spend {format_usd(spent)}."
                )
            _write_run_cap(db, new_cap)
            cap = new_cap
        elif cap > 0 and spent >= cap:
            raise ValueError(
                f"Run spent {format_usd(spent)} of {format_usd(cap)} cap: raise the cap to resume."
            )
        run.parked = False
        run.park_reason = None
        run.cost_warned = False
        run.claimed_by = None
        run.claimed_at = None
        prior = f"{run.notes}\n" if run.notes else ""
        run.notes = prior + f"resumed by user {user.id} under cap {format_usd(cap)}"
    audit.append(
        action_class="cost",
        decision="resume",
        line=f"run={run_id} by={user.id} cap_usd={cap}",
    )
    return {"run_id": run_id, "cap": cap}
