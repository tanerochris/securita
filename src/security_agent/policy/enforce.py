"""Guardrail checkpoints: pre-patch, pre-deliver, ingest silence.

Checkpoints evaluate live confirmed rules (D7) and translate the
winning effect: `block` stops the action with a cited marker,
`require_approval` routes through a policy gate, `silence` parks the
finding with a policy reason. Evaluation failures raise
PolicyStoreError so callers park the run (D8) — except ingestion
silence, where the safe default (findings stay visible) needs no park.
"""

import logging
from typing import Any, cast

from sqlalchemy import case, or_, select, update
from sqlalchemy.engine import CursorResult

from security_agent.audit import get_shared_log
from security_agent.control.lifecycle import transition_finding
from security_agent.db.models import (
    Approval,
    Finding,
    FindingStatus,
    GateAction,
    GateStatus,
    Proposal,
    ScanRun,
)
from security_agent.db.session import session_scope
from security_agent.policy.rules import Decision, FindingView, applicable_rules
from security_agent.policy.service import PolicyStoreError, tables_ok

log = logging.getLogger(__name__)
audit = get_shared_log()


def _decide(repo_id: int | None, task: str, view: FindingView) -> Decision | None:
    """Evaluate live rules; store failures become PolicyStoreError (D8)."""
    if not tables_ok():
        return None  # migration pending: no rules can exist yet
    try:
        winners = applicable_rules(repo_id, task, view)
    except Exception as exc:
        raise PolicyStoreError(f"policy evaluation failed: {exc}") from exc
    if not winners:
        return None
    top = winners[0]
    return Decision(
        rule_key=top.rule_key, version=top.version, effect=top.effect, reason=top.reason
    )


def _latest_gate(repo_id: int, target: str) -> Approval | None:
    with session_scope() as db:
        gate = db.scalar(
            select(Approval)
            .where(
                Approval.repo_id == repo_id,
                Approval.action == GateAction.POLICY,
                Approval.target == target,
            )
            .order_by(Approval.id.desc())
            .limit(1)
        )
        if gate is not None:
            db.expunge(gate)
        return gate


def _approval_outcome(
    repo_id: int, target: str, decision: Decision, *, proposal_id: int | None = None
) -> str:
    """'approved' | 'awaiting' | 'denied' for a require_approval effect."""
    from security_agent.control.gates import request_gate

    gate = _latest_gate(repo_id, target)
    if gate is not None and gate.status == GateStatus.APPROVED:
        return "approved"
    if gate is not None and gate.status == GateStatus.PENDING:
        return "awaiting"
    if gate is not None and gate.status in (GateStatus.DENIED, GateStatus.EXPIRED):
        if gate.requeues >= 3 and gate.status == GateStatus.EXPIRED:
            return "denied"  # terminal: re-queue budget spent
        if gate.status == GateStatus.DENIED:
            return "denied"
    request_gate(
        repo_id,
        GateAction.POLICY,
        target,
        proposal_id=proposal_id,
        reason=f"Policy review required — {decision.cite()}",
    )
    return "awaiting"


def _mark_blocked(finding_id: int, decision: Decision) -> None:
    with session_scope() as db:
        row = db.get(Finding, finding_id)
        if row is None:
            return
        row.policy_block = {
            "rule_key": decision.rule_key,
            "rule_version": decision.version,
            "reason": decision.reason,
        }
    audit.append(
        action_class="policy",
        decision="block",
        line=f"finding={finding_id} rule={decision.rule_key} v{decision.version}",
    )


def _clear_blocked(finding_id: int) -> None:
    with session_scope() as db:
        row = db.get(Finding, finding_id)
        if row is not None and row.policy_block:
            row.policy_block = None


def pre_patch_check(repo_id: int, run_id: int, findings: list[Finding]) -> dict[str, list[int]]:
    """Sort patch candidates into proceed / blocked / awaiting.

    Findings whose require_approval gate was approved proceed; denied
    gates behave as blocks. Silence matches found this late are applied
    on the spot (the finding leaves the patch path via SILENT status).
    Raises PolicyStoreError when rules cannot be evaluated (D8: park).
    """
    proceed: list[int] = []
    blocked: list[int] = []
    awaiting: list[int] = []
    silenced: list[int] = []
    for finding in findings:
        if finding.policy_block:
            _clear_blocked(finding.id)  # checkpoint re-evaluates live rules
        try:
            decision = _decide(repo_id, "patch", FindingView.from_finding(finding))
        except PolicyStoreError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed (D8)
            raise PolicyStoreError(f"policy evaluation failed: {exc}") from exc
        if decision is None:
            proceed.append(finding.id)
            continue
        if decision.effect == "silence":
            try:
                transition_finding(
                    finding.id,
                    FindingStatus.SILENT,
                    reason=f"policy:{decision.rule_key}",
                )
            except ValueError as exc:
                log.warning("late policy silence failed for %d: %s", finding.id, exc)
                proceed.append(finding.id)
                continue
            audit.append(
                action_class="policy",
                decision="silence",
                line=f"finding={finding.id} rule={decision.rule_key} v{decision.version}",
            )
            silenced.append(finding.id)
            continue
        if decision.effect == "block":
            _mark_blocked(finding.id, decision)
            blocked.append(finding.id)
            continue
        if decision.effect == "require_approval":
            target = f"policy:patch:repo={repo_id}:pkg={finding.package}:adv={finding.advisory_id}"
            outcome = _approval_outcome(repo_id, target, decision)
            if outcome == "approved":
                proceed.append(finding.id)
            elif outcome == "awaiting":
                awaiting.append(finding.id)
                audit.append(
                    action_class="policy",
                    decision="awaiting",
                    line=f"finding={finding.id} rule={decision.rule_key}",
                )
            else:
                _mark_blocked(finding.id, decision)
                blocked.append(finding.id)
            continue
        proceed.append(finding.id)  # pragma: no cover - allow never wins
    if blocked or awaiting:
        with session_scope() as db:
            run = db.get(ScanRun, run_id)
            if run is not None:
                prior = f"{run.notes}\n" if run.notes else ""
                run.notes = prior + f"policy: {len(blocked)} blocked, {len(awaiting)} awaiting"
    return {
        "proceed": proceed,
        "blocked": blocked,
        "awaiting": awaiting,
        "silenced": silenced,
    }


def _proposal_findings(proposal: Proposal) -> list[Finding]:
    with session_scope() as db:
        rows = list(db.scalars(select(Finding).where(Finding.id.in_(proposal.finding_ids or []))))
        for r in rows:
            db.expunge(r)
        return rows


def pre_deliver_check(repo_id: int, run_id: int, proposals: list[Proposal]) -> dict[str, list[int]]:
    """Sort pending proposals into deliver / held.

    Held covers blocks and unapproved gates; the proposal stays OPEN and
    is reconsidered on the next run. Raises PolicyStoreError (D8: park).
    """
    from security_agent.policy.constants import EFFECT_RANK

    deliver: list[int] = []
    held: list[int] = []
    for proposal in proposals:
        verdict: Decision | None = None
        try:
            for finding in _proposal_findings(proposal):
                decision = _decide(repo_id, "deliver", FindingView.from_finding(finding))
                # Silence applies at ingestion, not delivery: in-flight
                # proposals stay operator-visible until closed by hand.
                if decision is None or decision.effect == "silence":
                    continue
                if verdict is None or (EFFECT_RANK[decision.effect] >= EFFECT_RANK[verdict.effect]):
                    verdict = decision
        except PolicyStoreError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed (D8)
            raise PolicyStoreError(f"policy evaluation failed: {exc}") from exc
        if verdict is None:
            deliver.append(proposal.id)
            continue
        if verdict.effect == "block":
            held.append(proposal.id)
            audit.append(
                action_class="policy",
                decision="block",
                line=f"proposal={proposal.id} rule={verdict.rule_key} v{verdict.version}",
            )
            continue
        outcome = _approval_outcome(
            repo_id,
            f"policy:deliver:proposal={proposal.id}",
            verdict,
            proposal_id=proposal.id,
        )
        if outcome == "approved":
            deliver.append(proposal.id)
        else:
            held.append(proposal.id)
            audit.append(
                action_class="policy",
                decision="awaiting" if outcome == "awaiting" else "block",
                line=f"proposal={proposal.id} rule={verdict.rule_key}",
            )
    if held:
        with session_scope() as db:
            run = db.get(ScanRun, run_id)
            if run is not None:
                prior = f"{run.notes}\n" if run.notes else ""
                run.notes = prior + f"policy: {len(held)} proposals held"
    return {"deliver": deliver, "held": held}


def apply_ingest_silence(repo_id: int, finding_ids: list[int]) -> int:
    """Silence new findings matching `silence` rules; returns the count.

    Only silence applies at ingestion — there is no action to block yet.
    Failures leave findings visible with a warning (the safe default),
    never a park: visibility is not the failure D8 guards.
    """
    if not finding_ids or not tables_ok():
        return 0
    silenced = 0
    for finding_id in finding_ids:
        with session_scope() as db:
            row = db.get(Finding, finding_id)
            if row is None or row.status != FindingStatus.OPEN:
                continue
            db.expunge(row)
        try:
            decision = _decide(repo_id, "ingest", FindingView.from_finding(row))
        except PolicyStoreError as exc:
            log.warning("policy ingest check failed; findings stay visible: %s", exc)
            return silenced
        if decision is None or decision.effect != "silence":
            continue
        try:
            transition_finding(
                finding_id, FindingStatus.SILENT, reason=f"policy:{decision.rule_key}"
            )
        except ValueError:
            continue  # raced a verdict flip; lifecycle owns the status
        silenced += 1
        audit.append(
            action_class="policy",
            decision="silence",
            line=f"finding={finding_id} rule={decision.rule_key} v{decision.version}",
        )
    return silenced


def park_for_policy(run_id: int, reason: str) -> bool:
    """Park a run that cannot verify guardrails (D8). True if flipped."""
    from security_agent.notify import notify_event

    park_msg = f"parked: policy store unreachable ({reason})"
    with session_scope() as db:
        res = db.execute(
            update(ScanRun)
            .where(ScanRun.id == run_id, ScanRun.parked.is_(False))
            .values(
                parked=True,
                park_reason=f"policy store unreachable: {reason}",
                notes=case(
                    (or_(ScanRun.notes.is_(None), ScanRun.notes == ""), park_msg),
                    else_=ScanRun.notes + "\n" + park_msg,
                ),
            )
        )
        flipped = (cast("CursorResult[Any]", res).rowcount or 0) == 1
    if not flipped:
        return False
    audit.append(action_class="policy", decision="park", line=f"run={run_id} reason={reason}")
    try:
        notify_event(
            "high",
            f"run {run_id} parked: policy store unreachable",
            f"Run {run_id} parked because guardrails could not be verified "
            f"({reason}). Nothing was patched or delivered. Resume from the "
            "dashboard once the policy store is reachable.",
            link="/settings",
            kind="policy-park",
        )
    except Exception as exc:  # noqa: BLE001 - notify never breaks the park
        log.warning("policy park notification failed: %s", exc)
    return True


def policy_block_note(finding_id: int) -> str | None:
    """Human-readable block citation for dashboards, or None."""
    with session_scope() as db:
        row = db.get(Finding, finding_id)
        marker = dict(row.policy_block or {}) if row else {}
    if not marker:
        return None
    return (
        f"Blocked by policy rule {marker.get('rule_key')} "
        f"v{marker.get('rule_version')}: {marker.get('reason')}"
    )
