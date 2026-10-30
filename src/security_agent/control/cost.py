"""Cost control: token ledger, per-run caps, park/resume, spend alerts (NFR-8).

Per-run cap (default 1M tokens) warns at 80% and hard-stops by parking
the run; parked runs resume only under a raised cap via an
Owner/Maintainer. Daily spend alerts fire once per level per day.
`CostCapExceeded` inherits plain Exception deliberately: the patch
repair loop swallows (PatchError, ScanError, RuntimeError,
TimeoutError), and a parked run must abort, never retry.
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


class CostCapExceeded(Exception):
    """Per-run token cap hit: the run is parked, abort the pipeline."""


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


def _cap_in_session(db) -> int:
    """Per-run token cap read inside an open session (no nested session)."""
    row = db.get(NotifyState, "cost.run_cap")
    if row is not None:
        try:
            return max(1, int(row.value))
        except ValueError:
            pass
    return max(1, get_settings().run_token_cap)


def effective_cap() -> int:
    """Per-run token cap: install override wins, else the env default."""
    with session_scope() as db:
        return _cap_in_session(db)


def set_cap(value: int, user: User) -> int:
    """Owner/Maintainer raises (or lowers) the install-wide per-run cap."""
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may change cost caps.")
    if value < 1:
        raise ValueError("Cap must be at least 1 token.")
    with session_scope() as db:
        row = db.get(NotifyState, "cost.run_cap")
        if row is None:
            db.add(NotifyState(key="cost.run_cap", value=str(value)))
        else:
            row.value = str(value)
    audit.append(
        action_class="cost", decision="cap", line=f"cap={value} by={user.id} role={user.role.value}"
    )
    return value


def _price_per_token() -> float:
    return max(0.0, get_settings().model_price_per_mtok_usd) / 1_000_000


def _try_park_run(db, run_id: int, usage: int, cap: int) -> bool:
    """Guarded park flip; True only when this call flipped the flag."""
    park_msg = f"parked: token cap hit ({usage}/{cap} tokens)"
    res = db.execute(
        update(ScanRun)
        .where(
            ScanRun.id == run_id,
            ScanRun.parked.is_(False),
            ScanRun.token_usage >= cap,
        )
        .values(
            parked=True,
            park_reason=f"token cap hit: {usage} >= {cap}",
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
            ScanRun.token_usage >= warn_at,
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
    """Ledger one model call; warn/park at the cap (run-bound calls only).

    ONE session, no nested sessions: the cap read, the ModelUsage
    insert, and the usage increment share a single transaction, and
    guarded flag updates (rowcount decides) keep concurrent callers
    to exactly one warn and one park. Spend alerts run for every call
    including run-less ones. Raises CostCapExceeded whenever this call
    finds usage at/over cap; alerts fire only when this call flipped
    the flag.
    """
    total = max(0, prompt_tokens) + max(0, completion_tokens)
    cost = total * _price_per_token()
    warned = parked = False
    usage = 0
    cap = 0
    run_found = False
    with session_scope() as db:
        cap = _cap_in_session(db)
        warn_at = cap * get_settings().run_token_warn_fraction
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
            incremented = db.scalar(
                update(ScanRun)
                .where(ScanRun.id == run_id)
                .values(token_usage=func.coalesce(ScanRun.token_usage, 0) + total)
                .returning(ScanRun.token_usage)
            )
            if incremented is not None:
                run_found = True
                usage = incremented or 0
                if usage >= cap:
                    parked = _try_park_run(db, run_id, usage, cap)
                elif usage >= warn_at:
                    warned = _try_warn_run(db, run_id, warn_at)
    # Alerts fire after commit; the park abort raises past them.
    if warned:
        _alert_cost(
            "medium",
            f"run {run_id} at {usage} tokens (cap {cap})",
            "warn",
            f"Run {run_id} passed 80% of its token cap.",
        )
    if parked:
        _alert_cost(
            "high",
            f"run {run_id} parked at {usage} tokens",
            "parked",
            f"Run {run_id} hit its token cap and parked. Raise the cap and resume "
            "from the dashboard to continue.",
        )
    if run_found and usage >= cap:
        raise CostCapExceeded(f"run {run_id} parked: token cap hit ({usage} tokens)")
    check_spend_alerts()
    return {"total": total, "cost_usd": cost, "run_usage": usage}


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
                    "reason": run.park_reason or "",
                }
            )
            db.expunge(run)
        return out


def resume_run(run_id: int, user: User, *, new_cap: int | None = None) -> dict:
    """Unpark a run; resumes only under a raised cap (NFR-8 D5).

    When usage already covers the effective cap, `new_cap` (above
    usage) is required and becomes the install cap. Clears the claim
    so the next worker pass picks the run up; the pipeline re-runs
    from the top (scan/patch/deliver dedup keeps it safe).
    """
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may resume parked runs.")
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        if run is None:
            raise ValueError(f"Unknown run {run_id}.")
        if not run.parked:
            raise ValueError(f"Run {run_id} is not parked.")
        usage = run.token_usage or 0
        cap = effective_cap()
        if new_cap is not None:
            if new_cap <= usage:
                raise ValueError(f"New cap {new_cap} must exceed usage {usage}.")
            state = db.get(NotifyState, "cost.run_cap")
            if state is None:
                db.add(NotifyState(key="cost.run_cap", value=str(new_cap)))
            else:
                state.value = str(new_cap)
            cap = new_cap
        elif usage >= cap:
            raise ValueError(f"Run used {usage}/{cap} tokens: raise the cap to resume.")
        run.parked = False
        run.park_reason = None
        run.cost_warned = False
        run.claimed_by = None
        run.claimed_at = None
        prior = f"{run.notes}\n" if run.notes else ""
        run.notes = prior + f"resumed by user {user.id} under cap {cap}"
    audit.append(
        action_class="cost",
        decision="resume",
        line=f"run={run_id} by={user.id} cap={cap}",
    )
    return {"run_id": run_id, "cap": cap}
