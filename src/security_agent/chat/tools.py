"""Chat tools: backend-direct, role-checked, reusing router control functions.

Every tool takes the logged-in user and enforces the same role gate as its
dashboard counterpart (settled #3). Reporters read; Developers trigger scans;
approvers decide gates and operational writes; Owners own routes/digests and
delegations. Control functions that already check roles raise PermissionError,
which the agent turns into a denial message.
"""

from security_agent.chat import cards
from security_agent.db.models import Role, User

_APPROVER = (Role.OWNER, Role.MAINTAINER)
_DEVELOPER = (Role.OWNER, Role.MAINTAINER, Role.DEVELOPER)


def _require(user: User, roles: tuple[Role, ...], what: str) -> None:
    if user.role not in roles:
        raise PermissionError(f"{what} needs {', '.join(r.value for r in roles)}.")


# --- reads (every signed-in role, Reporter included) ---


def read_repos(user: User) -> dict:
    from security_agent.control import repos as repo_svc

    _ = user
    repos = repo_svc.list_repos()
    if not repos:
        return {"text": "No repos connected yet."}
    lines = [f"#{r.id} {r.name} ({r.kind.value})" for r in repos]
    return {"text": "Connected repos:\n" + "\n".join(lines)}


def read_findings(user: User, repo_id: int) -> dict:
    from security_agent.control import lifecycle

    _ = user
    rows = lifecycle.list_open_findings(repo_id)
    if not rows:
        return {"text": f"Repo #{repo_id}: no open findings."}
    lines = [
        f"- {f.package} {f.installed_version}: {f.advisory_id} "
        f"[score {f.severity_score if f.severity_score is not None else '?'}]"
        f"{' KEV' if f.kev_exploited else ''}"
        for f in rows[:30]
    ]
    extra = f"\n…and {len(rows) - 30} more." if len(rows) > 30 else ""
    return {"text": f"Repo #{repo_id} open findings ({len(rows)}):\n" + "\n".join(lines) + extra}


def read_patches(user: User, repo_id: int) -> dict:
    from security_agent.control import lifecycle

    _ = user
    rows = lifecycle.list_repo_proposals(repo_id)[:20]
    if not rows:
        return {"text": f"Repo #{repo_id}: no patch proposals."}
    lines = [
        f"- #{p.id} {p.package_from} → {p.package_to}"
        + (f" ({p.pr_state}: {p.pr_url})" if p.pr_url else " (no PR yet)")
        for p in rows
    ]
    return {"text": f"Repo #{repo_id} proposals:\n" + "\n".join(lines)}


def read_runs(user: User, repo_id: int) -> dict:
    from security_agent.control import lifecycle

    _ = user
    rows = lifecycle.list_repo_runs(repo_id)
    if not rows:
        return {"text": f"Repo #{repo_id}: no scan runs yet."}
    lines = [f"- run #{r.id}: {r.status.value} ({r.trigger.value})" for r in rows[:10]]
    return {"text": f"Repo #{repo_id} recent runs:\n" + "\n".join(lines)}


def read_run(user: User, repo_id: int, run_id: int) -> dict:
    from security_agent.control import lifecycle

    _ = user
    run = lifecycle.get_run(run_id)
    if run is None or run.repo_id != repo_id:
        raise ValueError(f"Unknown run #{run_id} on repo #{repo_id}.")
    findings = lifecycle.list_run_findings(run_id)
    lines = [f"- {f.package} {f.installed_version}: {f.advisory_id}" for f in findings[:20]]
    return {
        "text": f"Run #{run_id} on repo #{repo_id}: {run.status.value}.\n"
        + f"Findings ({len(findings)}):\n"
        + ("\n".join(lines) if lines else "(none)")
    }


def read_pending_gates(user: User) -> dict:
    from security_agent.control import gates

    pending = gates.list_pending_gates()
    if not pending:
        return {"text": "No pending approval gates.", "card": {"kind": "gates", "gates": []}}
    items = []
    lines = []
    for g in pending:
        ctx = gates.gate_context(g)
        can = gates.may_decide(user, g.action)
        items.append(
            {
                "gate_id": g.id,
                "action": g.action.value,
                "target": str(ctx.get("target", f"proposal #{g.proposal_id}")),
                "can_decide": can,
            }
        )
        lines.append(
            f"- gate #{g.id}: {g.action.value} on {items[-1]['target']}"
            + ("" if can else " (you cannot decide this)")
        )
    return {
        "text": "Pending approval gates:\n" + "\n".join(lines),
        "card": {"kind": "gates", "gates": items},
    }


def read_news(user: User, repo_id: int | None = None) -> dict:
    from security_agent.worker.news_intel import list_repo_news

    _ = user
    if repo_id is None:
        return {"text": "Pick a repo to see its security news.", "untrusted": False}
    items = list_repo_news(repo_id)[:15]
    if not items:
        return {"text": f"Repo #{repo_id}: no linked news."}
    lines = [f"- {n.title} ({n.url})" for n in items]
    # Feed content is attacker-influenceable: the agent fences it as data.
    return {"text": "\n".join(lines), "untrusted": True, "source": "news feeds"}


def read_policies(user: User, repo_id: int | None = None) -> dict:
    from security_agent.policy import rules as rule_svc
    from security_agent.policy.service import list_documents

    _ = user
    docs = list_documents(repo_id=repo_id)
    rules = rule_svc.list_rules(repo_id=repo_id)
    lines = [f"doc {d.doc_key} v{d.version} ({d.source})" for d in docs[:10]]
    lines += [f"rule {r.rule_key}: {r.effect}" for r in rules[:10]]
    if not lines:
        return {"text": "No policy documents or rules in scope."}
    return {"text": "Policies:\n" + "\n".join(lines), "untrusted": True, "source": "policy docs"}


def read_notifications(user: User) -> dict:
    from security_agent.control import notifications as notif_svc

    rows = notif_svc.list_notifications(user.id, limit=15)
    if not rows:
        return {"text": "No notifications."}
    lines = [f"- {n['title']}" for n in rows]
    unread = notif_svc.unread_count(user.id)
    return {"text": f"Notifications ({unread} unread):\n" + "\n".join(lines)}


# --- dashboard-only refusals (settled #2) ---


def refuse_dashboard_only(kind: str) -> dict:
    links = {"accounts": "/accounts", "secrets": "/repos"}
    return {"refusal": True, "card": cards.dashboard_only_card(kind, links[kind])}


# --- write intents: always return a confirm card, never execute (settled #2) ---


def want_scan(user: User, repo_id: int) -> dict:
    from security_agent.control import repos as repo_svc

    _require(user, _DEVELOPER, "Scan-now")
    names = {r.id: r.name for r in repo_svc.list_repos()}
    if repo_id not in names:
        raise ValueError(f"Unknown repo #{repo_id}.")
    card = cards.confirm_card("scan.now", {"repo_id": repo_id, "repo_name": names[repo_id]})
    return {"needs_confirm": True, "card": card}


def want_gate_decision(user: User, gate_id: int, approved: bool, reason: str = "") -> dict:
    from security_agent.control import gates

    gate = gates.get_gate(gate_id)
    if gate is None:
        raise ValueError(f"Unknown gate #{gate_id}.")
    if not gates.may_decide(user, gate.action):
        raise PermissionError("You cannot decide this gate.")
    ctx = gates.gate_context(gate)
    card = cards.confirm_card(
        "gate.decide",
        {
            "gate_id": gate_id,
            "approved": approved,
            "reason": reason,
            "gate_action": gate.action.value,
            "gate_target": str(ctx.get("target", f"proposal #{gate.proposal_id}")),
        },
    )
    return {"needs_confirm": True, "card": card}


def want_action(user: User, action: str, args: dict) -> dict:
    """Confirm-card intent for operational writes. Role-gated per action."""
    if action in ("notify.routes.save", "notify.digest.save", "delegation.create"):
        _require(user, (Role.OWNER,), action)
    elif action in (
        "deps.decide",
        "deps.decline",
        "deps.ignore",
        "deps.unignore",
        "policy.rule.create",
        "cost.cap.save",
    ):
        _require(user, _APPROVER, action)
    else:
        raise ValueError(f"Unknown chat action {action!r}; failing closed.")
    return {"needs_confirm": True, "card": cards.confirm_card(action, args)}


# --- confirmed execution: re-checks roles, then calls control functions ---


def execute_confirmed(user: User, action: str, args: dict) -> dict:
    if action == "scan.now":
        _require(user, _DEVELOPER, "Scan-now")
        from security_agent.worker.scheduler import trigger_manual_scan

        run = trigger_manual_scan(int(args["repo_id"]))
        return {
            "text": f"Scan started on {args.get('repo_name', 'repo')} (run #{run.id}).",
            "run_id": run.id,
            "repo_id": int(args["repo_id"]),
            "events_url": f"/repos/{args['repo_id']}/runs/{run.id}/events",
            "run_url": f"/repos/{args['repo_id']}/runs/{run.id}",
        }
    if action == "gate.decide":
        from security_agent.control import gates

        gate = gates.get_gate(int(args["gate_id"]))
        if gate is None:
            raise ValueError(f"Unknown gate #{args['gate_id']}.")
        if not gates.may_decide(user, gate.action):
            raise PermissionError("You cannot decide this gate.")
        gates.decide_gate(
            int(args["gate_id"]), user, bool(args["approved"]), reason=args.get("reason", "")
        )
        verb = "Approved" if args["approved"] else "Denied"
        return {"text": f"{verb} gate #{args['gate_id']}."}
    if action == "deps.decline":
        from security_agent.control import deps as deps_svc

        deps_svc.decline_version(
            int(args["dep_id"]), user, reason=args.get("reason", ""), repo_id=args.get("repo_id")
        )
        return {"text": f"Declined dependency update {args['dep_id']}."}
    if action == "deps.ignore":
        from security_agent.control import deps as deps_svc

        deps_svc.ignore_package(
            int(args["dep_id"]), user, reason=args.get("reason", ""), repo_id=args.get("repo_id")
        )
        return {"text": f"Ignored dependency update {args['dep_id']}."}
    if action == "deps.unignore":
        from security_agent.control import deps as deps_svc

        deps_svc.unignore_package(int(args["dep_id"]), user, repo_id=args.get("repo_id"))
        return {"text": f"Un-ignored dependency update {args['dep_id']}."}
    if action == "deps.decide":
        from security_agent.control import deps as deps_svc

        deps_svc.decide_report(
            int(args["report_id"]),
            user,
            list(args.get("included_keys", [])),
            reason=args.get("reason", ""),
            repo_id=args.get("repo_id"),
        )
        return {"text": f"Recorded decision on dependency report {args['report_id']}."}
    if action == "policy.rule.create":
        _require(user, _APPROVER, action)
        from security_agent.policy.rules import create_rule

        rule = create_rule(
            scope=args["scope"],
            effect=args["effect"],
            match=args.get("match") or {},
            reason=args["reason"],
            repo_id=args.get("repo_id"),
            tasks=args.get("tasks"),
            overridable=bool(args.get("overridable", True)),
            override_of=args.get("override_of"),
        )
        return {"text": f"Created policy rule {rule.rule_key}."}
    if action == "notify.routes.save":
        _require(user, (Role.OWNER,), action)
        from security_agent.notify import set_routes

        set_routes(args["severity"], [int(i) for i in args["channel_ids"]])
        return {"text": f"Routes for {args['severity']} saved."}
    if action == "notify.digest.save":
        _require(user, (Role.OWNER,), action)
        from security_agent.notify.digest import set_digest_schedule

        set_digest_schedule(enabled=bool(args["enabled"]), hour_utc=int(args["hour_utc"]))
        return {"text": "Digest schedule saved."}
    if action == "cost.cap.save":
        from security_agent.control.cost import set_run_cap

        value = set_run_cap(float(args["cap_usd"]), user)
        if value > 0:
            return {"text": f"Per-run spend cap set to ${value:.2f}."}
        return {"text": "Per-run cap disabled."}
    if action == "delegation.create":
        _require(user, (Role.OWNER,), action)
        from security_agent.app import accounts as accounts_svc
        from security_agent.control import gates

        delegate = accounts_svc.get_user_by_email(args["delegate_email"])
        if delegate is None:
            raise ValueError("Unknown user.")
        gates.delegate_approval(user.id, delegate.id, classes=args.get("classes"))
        return {"text": f"Delegated approval rights to {args['delegate_email']}."}
    raise ValueError(f"Unknown chat action {action!r}; failing closed.")
