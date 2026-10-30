"""Approval gates: request/decide/delegate/expire/execute (FR-9).

Merge, rotation, and publish are gated; single Owner/Maintainer approval
suffices. Developers approve only under Owner delegation. Timeouts deny
after 72h and re-queue (max 3); execution runs from the privileged
backend only, never from the sandbox.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from security_agent.audit import get_shared_log
from security_agent.db.models import (
    Approval,
    Delegation,
    GateAction,
    GateStatus,
    Proposal,
    Repo,
    RepoKind,
    Role,
    User,
)
from security_agent.db.session import session_scope

audit = get_shared_log()

GATE_TTL = timedelta(hours=72)
DELEGATION_TTL = timedelta(hours=24)
MAX_REQUEUES = 3


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def request_gate(
    repo_id: int,
    action: GateAction,
    target: str,
    *,
    proposal_id: int | None = None,
    request_run_id: int | None = None,
    reason: str = "",
) -> Approval:
    """Request a gate; idempotent per pending (action, target).

    A partial unique index serializes concurrent requests: losers return
    the winner instead of stacking duplicate pending gates.
    """
    pending = select(Approval).where(
        Approval.repo_id == repo_id,
        Approval.action == action,
        Approval.target == target,
        Approval.status == GateStatus.PENDING,
    )
    is_new = False
    with session_scope() as db:
        existing = db.scalar(pending)
        if existing is not None:
            db.expunge(existing)
            gate = existing
        else:
            gate = Approval(
                repo_id=repo_id,
                proposal_id=proposal_id,
                action=action,
                target=target,
                request_run_id=request_run_id,
                reason=reason or None,
                expires_at=datetime.now(UTC) + GATE_TTL,
            )
            try:
                with db.begin_nested():
                    db.add(gate)
                    db.flush()
            except IntegrityError:
                existing = db.scalar(pending)
                if existing is None:
                    raise
                gate = existing
                db.expunge(gate)
            else:
                db.expunge(gate)
                is_new = True
    if not is_new:
        return gate
    audit.append(
        action_class="gate",
        decision="request",
        line=f"repo={repo_id} action={action.value} target={target}",
    )
    # FR-9 D5: approval requests fan out to ALL channels (granting stays
    # dashboard + provider-side). After commit; failures never break delivery.
    from security_agent.notify import notify_event

    notify_event(
        "high",
        f"approval needed: {action.value} on {target[:200]}",
        f"Repo {repo_id} requests {action.value} approval for {target}. "
        f"Grant it from the dashboard approval queue. Reason: {reason or '—'}",
        link="/approvals",
        fan_out_all=True,
        kind="approval-request",
    )
    return gate


def active_delegation(delegate_id: int, action: GateAction) -> bool:
    now = datetime.now(UTC)
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Delegation).where(
                    Delegation.delegate_id == delegate_id,
                    Delegation.revoked_at.is_(None),
                )
            )
        )
        return any(
            _aware(d.expires_at) > now and (not d.classes or action.value in d.classes)
            for d in rows
        )


def may_decide(user: User, action: GateAction) -> bool:
    if user.role in (Role.OWNER, Role.MAINTAINER):
        return True
    return user.role == Role.DEVELOPER and active_delegation(user.id, action)


def decide_gate(gate_id: int, decider: User, approved: bool, *, reason: str = "") -> Approval:
    """Approve or deny a pending, unexpired gate. Expired gates are swept, not decided."""
    with session_scope() as db:
        gate = db.get(Approval, gate_id)
        if gate is None:
            raise ValueError(f"Unknown gate {gate_id}.")
        if gate.status != GateStatus.PENDING:
            raise ValueError(f"Gate {gate_id} is already {gate.status.value}.")
        if _aware(gate.expires_at) <= datetime.now(UTC):
            raise ValueError(f"Gate {gate_id} has expired.")
        if not may_decide(decider, gate.action):
            raise PermissionError("Owner, Maintainer, or delegated Developer only.")
        gate.status = GateStatus.APPROVED if approved else GateStatus.DENIED
        gate.decider_id = decider.id
        gate.source = "dashboard"
        gate.decided_at = datetime.now(UTC)
        if reason:
            gate.reason = reason
        db.flush()
        db.expunge(gate)
        audit.append(
            action_class="gate",
            decision="approved" if approved else "denied",
            line=f"gate={gate_id} decider={decider.id} role={decider.role.value}",
        )
        return gate


def delegate_approval(
    owner_id: int, delegate_id: int, *, classes: list[str] | None = None, hours: int = 24
) -> Delegation:
    """Owner grants time-boxed approval rights to a Developer (FR-9 D7)."""
    with session_scope() as db:
        owner = db.get(User, owner_id)
        delegate = db.get(User, delegate_id)
        if owner is None or owner.role != Role.OWNER:
            raise PermissionError("Only an Owner may delegate.")
        if delegate is None or delegate.role != Role.DEVELOPER:
            raise ValueError("Delegation targets Developers only.")
        if classes:
            unknown = set(classes) - {a.value for a in GateAction}
            if unknown:
                raise ValueError(f"Unknown gate classes: {sorted(unknown)}")
        row = Delegation(
            owner_id=owner_id,
            delegate_id=delegate_id,
            classes=classes,
            expires_at=datetime.now(UTC) + timedelta(hours=hours),
        )
        db.add(row)
        db.flush()
        db.expunge(row)
        audit.append(
            action_class="delegation",
            decision="grant",
            line=f"owner={owner_id} delegate={delegate_id} classes={classes or 'all'}",
        )
        return row


def revoke_delegation(delegation_id: int, owner_id: int) -> None:
    with session_scope() as db:
        row = db.get(Delegation, delegation_id)
        if row is None:
            return
        if row.owner_id != owner_id:
            raise PermissionError("Only the granting Owner may revoke.")
        row.revoked_at = datetime.now(UTC)
        audit.append(
            action_class="delegation", decision="revoke", line=f"delegation={delegation_id}"
        )


def sweep_expired_gates(now: datetime | None = None) -> dict:
    """Deny expired gates; auto re-queue with a note, up to MAX_REQUEUES (FR-9 D4)."""
    now = now or datetime.now(UTC)
    expired = requeued = 0
    with session_scope() as db:
        stale = list(db.scalars(select(Approval).where(Approval.status == GateStatus.PENDING)))
        for gate in stale:
            if _aware(gate.expires_at) > now:
                continue
            gate.status = GateStatus.EXPIRED
            gate.decided_at = now
            expired += 1
            audit.append(action_class="gate", decision="expired", line=f"gate={gate.id}")
            if gate.requeues < MAX_REQUEUES:
                db.add(
                    Approval(
                        repo_id=gate.repo_id,
                        proposal_id=gate.proposal_id,
                        action=gate.action,
                        target=gate.target,
                        request_run_id=gate.request_run_id,
                        reason=f"auto re-queue after 72h timeout (#{gate.requeues + 1})",
                        requeues=gate.requeues + 1,
                        expires_at=now + GATE_TTL,
                    )
                )
                requeued += 1
    return {"expired": expired, "requeued": requeued}


def resolve_gates_for_proposal(proposal_id: int, source: str) -> int:
    """Mark open merge gates approved when the merge is observed outside the dashboard."""
    resolved = 0
    with session_scope() as db:
        gates = list(
            db.scalars(
                select(Approval).where(
                    Approval.proposal_id == proposal_id,
                    Approval.action == GateAction.MERGE,
                    Approval.status.in_([GateStatus.PENDING, GateStatus.APPROVED]),
                )
            )
        )
        for gate in gates:
            gate.status = GateStatus.APPROVED
            gate.source = source
            gate.decided_at = datetime.now(UTC)
            if gate.reason is None:
                gate.reason = f"merged outside dashboard (observed via {source})"
            resolved += 1
            audit.append(
                action_class="gate",
                decision="observed",
                line=f"gate={gate.id} source={source}",
            )
    return resolved


def execute_merge(gate_id: int, executor: User | None) -> dict:
    """Privileged backend merge of an APPROVED gate. System callers pass None."""
    from security_agent.control.repos import get_merge_token
    from security_agent.worker.deliver import detect_provider, merge_pr

    with session_scope() as db:
        gate = db.get(Approval, gate_id)
        if gate is None:
            raise ValueError(f"Unknown gate {gate_id}.")
        if gate.action != GateAction.MERGE:
            raise ValueError("Only merge gates execute here.")
        if gate.status != GateStatus.APPROVED:
            raise PermissionError(f"Gate {gate_id} is {gate.status.value}, not approved.")
        if executor is not None and not may_decide(executor, gate.action):
            raise PermissionError("Owner, Maintainer, or delegated Developer only.")
        db.expunge(gate)
        repo = db.get(Repo, gate.repo_id)
        proposal = db.get(Proposal, gate.proposal_id) if gate.proposal_id else None
        if repo is not None:
            db.expunge(repo)
        if proposal is not None:
            db.expunge(proposal)
    if proposal is None or not proposal.pr_url:
        raise ValueError("Manual merge required: no provider PR for this gate.")
    if proposal.repo_id != gate.repo_id:
        raise ValueError("Gate/proposal repo mismatch; refusing to merge.")
    if repo is None or repo.kind != RepoKind.GIT:
        raise ValueError("Manual merge required: local repos merge in their checkout.")
    provided = detect_provider(repo.url or "")
    if provided is None:
        raise ValueError("Manual merge required: unknown provider.")
    token = get_merge_token(repo.id)
    if not token:
        raise ValueError("No merge credential configured for this repo.")
    merge_pr(proposal.pr_url, token)
    from security_agent.worker.deliver import sync_proposal_states

    synced = sync_proposal_states(repo.id)
    actor = f"user={executor.id}" if executor else "system=post-approval"
    audit.append(action_class="gate", decision="executed", line=f"gate={gate_id} {actor}")
    return {"status": "merged", "gate_id": gate_id, "sync": synced}


def get_gate(gate_id: int) -> Approval | None:
    with session_scope() as db:
        gate = db.get(Approval, gate_id)
        if gate is not None:
            db.expunge(gate)
        return gate


def list_pending_gates() -> list[Approval]:
    """Needs-action first: earliest expiry first, all repos."""
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Approval)
                .where(Approval.status == GateStatus.PENDING)
                .order_by(Approval.expires_at, Approval.id)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def list_gate_history(limit: int = 50) -> list[Approval]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Approval)
                .where(Approval.status != GateStatus.PENDING)
                .order_by(Approval.id.desc())
                .limit(limit)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def list_delegations() -> list[Delegation]:
    with session_scope() as db:
        rows = list(db.scalars(select(Delegation).order_by(Delegation.id.desc())))
        for r in rows:
            db.expunge(r)
        return rows


def gate_context(gate: Approval) -> dict:
    """Full decision context for the queue: repo, proposal, decider names."""
    from security_agent.db.models import Finding

    with session_scope() as db:
        repo = db.get(Repo, gate.repo_id)
        repo_name = repo.name if repo else f"repo#{gate.repo_id}"
        proposal = db.get(Proposal, gate.proposal_id) if gate.proposal_id else None
        advisories: list[str] = []
        if proposal is not None:
            findings = list(
                db.scalars(select(Finding).where(Finding.id.in_(proposal.finding_ids or [])))
            )
            advisories = sorted({f.advisory_id for f in findings})
        decider = db.get(User, gate.decider_id) if gate.decider_id else None
        return {
            "gate": gate,
            "repo_name": repo_name,
            "proposal": proposal,
            "advisories": advisories,
            "decider_email": decider.email if decider else None,
        }


def run_merge(repo_id: int, run_id: int, proposal_ids: list[int]) -> dict:
    """Graph merge node: execute APPROVED gates for delivered proposals, else skip."""
    from security_agent.db.models import ScanRun

    with session_scope() as db:
        if db.get(Repo, repo_id) is None or db.get(ScanRun, run_id) is None:
            raise ValueError(f"Unknown repo {repo_id} or run {run_id}.")
    merged: list[int] = []
    skipped: list[int] = []
    for pid in proposal_ids:
        with session_scope() as db:
            gate = db.scalar(
                select(Approval)
                .where(
                    Approval.repo_id == repo_id,
                    Approval.proposal_id == pid,
                    Approval.action == GateAction.MERGE,
                )
                .order_by(Approval.id.desc())
                .limit(1)
            )
            gate_id = gate.id if gate else None
            status = gate.status if gate else None
        if gate_id is None or status != GateStatus.APPROVED:
            skipped.append(pid)
            continue
        try:
            execute_merge(gate_id, None)
            merged.append(pid)
        except (ValueError, PermissionError, RuntimeError):
            skipped.append(pid)
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        if run is not None:
            prior = f"{run.notes}\n" if run.notes else ""
            run.notes = prior + f"merge: {len(merged)} merged, {len(skipped)} skipped"
    return {"status": "done", "merged": merged, "skipped": skipped}
