"""Structured guardrails: lifecycle, matching, and precedence (D1b/D1c/D2).

Rules are versioned like documents: `pending` blocks nothing, `confirmed`
enforces at checkpoints, `disabled` is the only delete. Evaluation is
most-restrictive-wins with repo scope breaking ties; a repo rule replaces
a platform rule only through an explicit `override_of` exception whose
target is current, confirmed, and overridable.
"""

import fnmatch
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from security_agent.audit import get_shared_log
from security_agent.db.models import PolicyDocument, PolicyRule, Repo
from security_agent.db.session import session_scope
from security_agent.policy.constants import EFFECT_RANK, EFFECTS, POLICY_TASKS
from security_agent.policy.service import PolicyError, _check_scope, _check_tasks

log = logging.getLogger(__name__)
audit = get_shared_log()

MATCH_KEYS = ("package", "advisory", "ecosystem", "max_severity")


@dataclass(frozen=True)
class FindingView:
    """The rule-visible slice of a finding."""

    package: str
    advisory_id: str
    ecosystem: str | None = None
    severity_score: float | None = None

    @classmethod
    def from_finding(cls, finding) -> "FindingView":
        return cls(
            package=finding.package or "",
            advisory_id=finding.advisory_id or "",
            ecosystem=finding.ecosystem,
            severity_score=finding.severity_score,
        )


@dataclass(frozen=True)
class Decision:
    """A fired guardrail: the winning rule plus how to cite it."""

    rule_key: str
    version: int
    effect: str
    reason: str

    def cite(self) -> str:
        return f"policy rule {self.rule_key} v{self.version}: {self.reason}"


def validate_match(match: dict | None) -> dict:
    """Normalize a rule match clause; raises PolicyError when unusable."""
    match = dict(match or {})
    unknown = [k for k in match if k not in MATCH_KEYS]
    if unknown:
        raise PolicyError(f"Unknown match keys: {unknown}; want one of {MATCH_KEYS}.")
    for key in ("package", "advisory", "ecosystem"):
        if match.get(key) is not None and not str(match[key]).strip():
            raise PolicyError(f"Match {key!r} must be a non-empty glob.")
    if match.get("max_severity") is not None:
        try:
            score = float(match["max_severity"])
        except (TypeError, ValueError) as exc:
            raise PolicyError("Match max_severity must be a number 0-10.") from exc
        if not 0 <= score <= 10:
            raise PolicyError("Match max_severity must be a number 0-10.")
        match["max_severity"] = score
    if not any(match.get(k) is not None for k in MATCH_KEYS):
        raise PolicyError("Rules need a non-empty match (e.g. package 'openssl').")
    return match


def _check_effect(effect: str, *, override_of: str | None) -> None:
    if effect not in EFFECTS:
        raise PolicyError(f"Unknown effect {effect!r}; want one of {EFFECTS}.")
    if effect == "allow" and not override_of:
        raise PolicyError("'allow' is valid only on an override_of exception (D2).")


def rule_matches(match: dict | None, view: FindingView) -> bool:
    """True when every present clause matches (absent clauses match all)."""
    match = match or {}
    package = match.get("package")
    if package and not fnmatch.fnmatchcase(view.package.lower(), str(package).lower()):
        return False
    advisory = match.get("advisory")
    if advisory and not fnmatch.fnmatchcase(view.advisory_id.upper(), str(advisory).upper()):
        return False
    ecosystem = match.get("ecosystem")
    if ecosystem and not fnmatch.fnmatchcase(
        (view.ecosystem or "").lower(), str(ecosystem).lower()
    ):
        return False
    ceiling = match.get("max_severity")
    if ceiling is not None and (
        view.severity_score is None or view.severity_score > float(ceiling)
    ):
        return False
    return True


def _task_applies(tasks: list | None, task: str | None) -> bool:
    return not tasks or not task or task in tasks


def create_rule(
    *,
    scope: str,
    effect: str,
    match: dict,
    reason: str,
    repo_id: int | None = None,
    tasks: list[str] | None = None,
    source_document_id: int | None = None,
    source_quote: str | None = None,
    overridable: bool = False,
    override_of: str | None = None,
    created_by: int | None = None,
) -> PolicyRule:
    """Author a rule as `pending` (extraction or hand-written form)."""
    _check_scope(scope, repo_id)
    _check_effect(effect, override_of=override_of)
    match = validate_match(match)
    tasks = _check_tasks(tasks)
    if tasks and any(t not in POLICY_TASKS for t in tasks):
        raise PolicyError(f"Tasks must come from {POLICY_TASKS}.")
    reason = (reason or "").strip()
    if not reason:
        raise PolicyError("Rules need a human-readable reason.")
    if scope == "repo":
        with session_scope() as db:
            if db.get(Repo, repo_id) is None:
                raise PolicyError(f"Unknown repo {repo_id}.")
    if source_document_id is not None:
        with session_scope() as db:
            doc = db.get(PolicyDocument, source_document_id)
            if doc is None:
                raise PolicyError(f"Unknown policy document {source_document_id}.")
            if doc.source == "readme":
                # D3 hard boundary: README text can never back a guardrail.
                raise PolicyError("README documents cannot back guardrails (D3).")
    rule_key = uuid.uuid4().hex[:16]
    with session_scope() as db:
        rule = PolicyRule(
            rule_key=rule_key,
            version=1,
            is_current=True,
            scope=scope,
            repo_id=repo_id,
            tasks=tasks,
            effect=effect,
            match=match,
            reason=reason,
            source_document_id=source_document_id,
            source_quote=(source_quote.strip() if source_quote else None),
            status="pending",
            overridable=bool(overridable),
            override_of=override_of,
            created_by=created_by,
        )
        db.add(rule)
        db.flush()
        db.expunge(rule)
    audit.append(
        action_class="policy",
        decision="rule-draft",
        line=f"key={rule_key} scope={scope} effect={effect}",
    )
    return rule


def get_rule(rule_key: str, *, version: int | None = None) -> PolicyRule | None:
    with session_scope() as db:
        stmt = select(PolicyRule).where(PolicyRule.rule_key == rule_key)
        stmt = (
            stmt.where(PolicyRule.version == version)
            if version is not None
            else stmt.where(PolicyRule.is_current.is_(True))
        )
        rule = db.scalar(stmt)
        if rule is not None:
            db.expunge(rule)
        return rule


def list_rules(
    *,
    scope: str | None = None,
    repo_id: int | None = None,
    status: str | None = None,
) -> list[PolicyRule]:
    """Current versions only, newest first."""
    with session_scope() as db:
        stmt = (
            select(PolicyRule).where(PolicyRule.is_current.is_(True)).order_by(PolicyRule.id.desc())
        )
        if scope is not None:
            stmt = stmt.where(PolicyRule.scope == scope)
        if repo_id is not None:
            stmt = stmt.where(PolicyRule.repo_id == repo_id)
        if status is not None:
            stmt = stmt.where(PolicyRule.status == status)
        rows = list(db.scalars(stmt))
        for r in rows:
            db.expunge(r)
        return rows


def rule_history(rule_key: str) -> list[PolicyRule]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(PolicyRule)
                .where(PolicyRule.rule_key == rule_key)
                .order_by(PolicyRule.version.desc())
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def _confirmable(rule: PolicyRule) -> PolicyRule:
    """The current row, plus override-target validation for exceptions."""
    if rule.status == "confirmed":
        return rule
    if rule.status != "pending":
        raise PolicyError(f"Rule {rule.rule_key} is {rule.status}; enable it first.")
    if rule.override_of:
        target = get_rule(rule.override_of)
        if target is None or not target.is_current or target.status != "confirmed":
            raise PolicyError(f"Override target {rule.override_of!r} is not a confirmed rule.")
        if target.scope != "platform":
            raise PolicyError("Only platform rules can be overridden.")
        if not target.overridable:
            raise PolicyError(f"Platform rule {rule.override_of!r} does not allow overrides.")
        if rule.scope != "repo" or rule.repo_id is None:
            raise PolicyError("Overrides must be repo-scoped rules.")
        if EFFECT_RANK[rule.effect] >= EFFECT_RANK[target.effect]:
            raise PolicyError(f"Override must be less restrictive than {target.effect}.")
    return rule


def confirm_rule(rule_key: str, *, user_id: int | None = None) -> PolicyRule:
    """Confirm a pending rule: it enforces from this moment (D1b).

    Confirmation is lifecycle, not content: no new version, but the
    confirmer and timestamp are recorded for the audit trail.
    """
    with session_scope() as db:
        rule = db.scalar(
            select(PolicyRule).where(
                PolicyRule.rule_key == rule_key, PolicyRule.is_current.is_(True)
            )
        )
        if rule is None:
            raise PolicyError(f"Unknown rule {rule_key!r}.")
        db.expunge(rule)
    _confirmable(rule)
    with session_scope() as db:
        row = db.scalar(
            select(PolicyRule).where(
                PolicyRule.rule_key == rule_key, PolicyRule.is_current.is_(True)
            )
        )
        if row is None:  # pragma: no cover - raced delete; fail loud
            raise PolicyError(f"Unknown rule {rule_key!r}.")
        row.status = "confirmed"
        row.confirmed_by = user_id
        row.confirmed_at = datetime.now(UTC)
        db.flush()
        db.expunge(row)
    audit.append(
        action_class="policy", decision="rule-confirm", line=f"key={rule_key} by={user_id}"
    )
    return row


def set_rule_status(rule_key: str, *, disabled: bool, user_id: int | None = None) -> None:
    """Disable (or re-enable) a rule. Deletes are disables (D7).

    Disabling a silence rule reopens the findings it silenced — the
    accepted risk no longer has an owner, so they return to OPEN.
    """
    from security_agent.db.models import Finding, FindingStatus

    with session_scope() as db:
        rule = db.scalar(
            select(PolicyRule).where(
                PolicyRule.rule_key == rule_key, PolicyRule.is_current.is_(True)
            )
        )
        if rule is None:
            raise PolicyError(f"Unknown rule {rule_key!r}.")
        effect = rule.effect
        if disabled:
            rule.status = "disabled"
        else:
            rule.status = "confirmed" if rule.confirmed_by is not None else "pending"
    if disabled and effect == "silence":
        with session_scope() as db:
            rows = list(
                db.scalars(
                    select(Finding).where(
                        Finding.status == FindingStatus.SILENT,
                        Finding.silent_reason == f"policy:{rule_key}",
                    )
                )
            )
            for row in rows:
                row.status = FindingStatus.OPEN
                row.silent_reason = None
        if rows:
            audit.append(
                action_class="policy",
                decision="reopen",
                line=f"rule={rule_key} reopened={len(rows)}",
            )
    audit.append(
        action_class="policy",
        decision="rule-disable" if disabled else "rule-enable",
        line=f"key={rule_key} by={user_id}",
    )


def edit_rule(
    rule_key: str,
    *,
    effect: str | None = None,
    match: dict | None = None,
    reason: str | None = None,
    tasks: list[str] | None | object = ...,
    overridable: bool | None = None,
    user_id: int | None = None,
) -> PolicyRule:
    """Append a new current version; status carries over (editor is authorized)."""
    with session_scope() as db:
        current = db.scalar(
            select(PolicyRule).where(
                PolicyRule.rule_key == rule_key, PolicyRule.is_current.is_(True)
            )
        )
        if current is None:
            raise PolicyError(f"Unknown rule {rule_key!r}.")
        if current.status == "disabled":
            raise PolicyError("Enable the rule before editing it.")
        snapshot: dict[str, Any] = {
            "scope": current.scope,
            "repo_id": current.repo_id,
            "effect": current.effect,
            "match": dict(current.match or {}),
            "tasks": list(current.tasks) if current.tasks else None,
            "reason": current.reason,
            "source_document_id": current.source_document_id,
            "source_quote": current.source_quote,
            "status": current.status,
            "overridable": current.overridable,
            "override_of": current.override_of,
            "confirmed_by": current.confirmed_by,
            "confirmed_at": current.confirmed_at,
            "version": current.version,
        }
    new_effect = effect if effect is not None else snapshot["effect"]
    _check_effect(new_effect, override_of=snapshot["override_of"])
    new_match = validate_match(match) if match is not None else snapshot["match"]
    new_tasks = snapshot["tasks"] if tasks is ... else _check_tasks(tasks)  # type: ignore[arg-type]
    new_reason = (reason.strip() if reason is not None else snapshot["reason"]) or ""
    if not new_reason:
        raise PolicyError("Rules need a human-readable reason.")
    if snapshot["override_of"] and new_effect != "allow":
        target = get_rule(snapshot["override_of"])
        if target is None or EFFECT_RANK[new_effect] >= EFFECT_RANK[target.effect]:
            raise PolicyError("Override must stay less restrictive than its target.")
    with session_scope() as db:
        current = db.scalar(
            select(PolicyRule).where(
                PolicyRule.rule_key == rule_key, PolicyRule.is_current.is_(True)
            )
        )
        if current is None:  # pragma: no cover - raced delete; fail loud
            raise PolicyError(f"Unknown rule {rule_key!r}.")
        current.is_current = False
        try:
            with db.begin_nested():
                rule = PolicyRule(
                    rule_key=rule_key,
                    version=snapshot["version"] + 1,
                    is_current=True,
                    scope=snapshot["scope"],
                    repo_id=snapshot["repo_id"],
                    tasks=new_tasks,
                    effect=new_effect,
                    match=new_match,
                    reason=new_reason,
                    source_document_id=snapshot["source_document_id"],
                    source_quote=snapshot["source_quote"],
                    status=snapshot["status"],
                    overridable=(
                        bool(overridable) if overridable is not None else snapshot["overridable"]
                    ),
                    override_of=snapshot["override_of"],
                    confirmed_by=user_id
                    if snapshot["status"] == "confirmed"
                    else snapshot["confirmed_by"],
                    confirmed_at=(
                        datetime.now(UTC)
                        if snapshot["status"] == "confirmed"
                        else snapshot["confirmed_at"]
                    ),
                    created_by=user_id,
                )
                db.add(rule)
                db.flush()
                db.expunge(rule)
        except IntegrityError as exc:
            raise PolicyError("Concurrent rule edit; retry.") from exc
    audit.append(
        action_class="policy",
        decision="rule-edit",
        line=f"key={rule_key} version={snapshot['version'] + 1}",
    )
    return rule


def applicable_rules(repo_id: int | None, task: str | None, view: FindingView) -> list[PolicyRule]:
    """Current + confirmed rules matching scope, task, and finding.

    Platform rules always apply; repo rules apply to their repo.
    Overrides replace their target for the owning repo only.
    """
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(PolicyRule)
                .where(
                    PolicyRule.is_current.is_(True),
                    PolicyRule.status == "confirmed",
                )
                .order_by(PolicyRule.id)
            )
        )
        for r in rows:
            db.expunge(r)
    matched = [
        r
        for r in rows
        if (r.scope == "platform" or (repo_id is not None and r.repo_id == repo_id))
        and _task_applies(r.tasks, task)
        and rule_matches(r.match, view)
    ]
    by_key = {r.rule_key: r for r in matched}
    overridden: set[str] = set()
    for r in matched:
        if not r.override_of:
            continue
        target = by_key.get(r.override_of)
        if (
            target is None
            or target.scope != "platform"
            or not target.overridable
            or EFFECT_RANK[r.effect] >= EFFECT_RANK[target.effect]
        ):
            # Stale or invalid exception (target edited since confirm):
            # the platform rule stands; the override is inert.
            log.warning("inert policy override %s (target %s)", r.rule_key, r.override_of)
            continue
        overridden.add(r.override_of)
        if r.effect == "allow":
            by_key.pop(r.rule_key, None)  # exception lifts the rule entirely
    winners = [r for k, r in by_key.items() if k not in overridden]
    # Most restrictive wins; repo scope breaks ties; id is the final tiebreak.
    winners.sort(key=lambda r: (-EFFECT_RANK[r.effect], 0 if r.scope == "repo" else 1, r.id))
    return winners


def evaluate(repo_id: int | None, task: str | None, view: FindingView) -> Decision | None:
    """The winning guardrail for one finding, or None when nothing matches."""
    winners = applicable_rules(repo_id, task, view)
    if not winners:
        return None
    top = winners[0]
    return Decision(
        rule_key=top.rule_key, version=top.version, effect=top.effect, reason=top.reason
    )
