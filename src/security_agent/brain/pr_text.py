"""Model-written PR titles/bodies for patch delivery (FR-5).

`render_pr` in worker/deliver.py stays the deterministic fallback; this
module asks the chat model for a short human-readable summary first, so
a 33-advisory bump reads as one line instead of a pasted CVE list.

Fail-loud on provider errors, template otherwise: a disabled flag,
unparseable output, and validation failures return None and the caller
keeps the template. A missing or broken brain raises BrainError (the
run parks, never silently keeps delivering); CostCapExceeded propagates
as before.
"""

import json
import logging
import re

from security_agent.prompts import render_prompt

log = logging.getLogger(__name__)

_TITLE_MAX_CHARS = 150
_BODY_MAX_CHARS = 8000
_PROMPT_ADVISORIES = 30
_PROMPT_VERIFICATION_CHARS = 2000


def _pr_prompt(
    package: str,
    from_version: str,
    to_version: str,
    advisories: list[str],
    kev: list[str],
    verifications: list[str],
    grouping: str,
    ignored: list[str],
    dashboard: str,
    *,
    template: str | None = None,
) -> str:
    advs = sorted(set(advisories))
    shown = advs[:_PROMPT_ADVISORIES]
    blob = ", ".join(shown)
    if len(advs) > len(shown):
        blob += f", and {len(advs) - len(shown)} more"
    prompt = render_prompt(
        "draft_pr",
        package=package,
        from_version=from_version,
        to_version=to_version,
        advisory_count=str(len(advs)),
        advisories=blob or "none",
        kev=", ".join(sorted(set(kev))) or "none",
        verification="; ".join(verifications)[:_PROMPT_VERIFICATION_CHARS] or "none",
        grouping=grouping or "single package",
        ignored="; ".join(ignored) or "none",
        dashboard=dashboard,
    )
    if template:
        prompt += render_prompt("draft_pr_template_block", template=template)
    return prompt


def _parse_pr_text(
    content: str, dashboard: str, template: str | None = None
) -> tuple[str, str] | None:
    """(title, body) from model output, else None (caller keeps template)."""
    text = (content or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    title, body = data.get("title"), data.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        return None
    title, body = title.strip(), body.strip()
    if (
        not title.startswith("[security] ")
        or len(title) <= len("[security] ")
        or len(title) > _TITLE_MAX_CHARS
        or "\n" in title
    ):
        return None
    if not body:
        return None
    body = body[:_BODY_MAX_CHARS]
    if dashboard and dashboard not in body:
        body += f"\nDashboard: {dashboard}"
    if template:
        headings = [ln.strip() for ln in template.splitlines() if ln.lstrip().startswith("#")]
        if any(h and h not in body for h in headings):
            return None  # template structure dropped: caller keeps the fallback
    return title, body


def generate_pr_text(
    package: str,
    from_version: str,
    to_version: str,
    advisories: list[str],
    kev: list[str],
    verifications: list[str],
    grouping: str,
    ignored: list[str],
    dashboard: str,
    *,
    model=None,
    template: str | None = None,
    repo_id: int | None = None,
) -> tuple[str, str] | None:
    """Model-written (title, body); None when the template should win.

    An explicitly injected model skips the enabled gate so tests can
    drive this deterministically; the live path needs the flag,
    otherwise no request is attempted. Provider failures raise
    BrainError past the template (loud: the run parks).
    """
    from security_agent.brain import BrainError, get_chat_model, tracked_invoke
    from security_agent.config import get_settings
    from security_agent.control.cost import CostCapExceeded

    if model is None:
        if not get_settings().pr_text_model_enabled:
            return None
        bound = get_chat_model()
    else:
        bound = model
    prompt = _pr_prompt(
        package,
        from_version,
        to_version,
        advisories,
        kev,
        verifications,
        grouping,
        ignored,
        dashboard,
        template=template,
    )
    policy_block = ""
    try:
        from security_agent.control.cost import current_run_id
        from security_agent.policy.retrieve import retrieve_policy_context

        top = " ".join(sorted(set(advisories))[:5])
        query = f"{package} {top} pull request template title description commit changelog"
        policy_block, _ = retrieve_policy_context(
            repo_id,
            "pr-text",
            query,
            run_id=current_run_id(),
        )
    except Exception as exc:  # noqa: BLE001 - guidance never breaks PR copy
        log.warning("policy guidance for PR copy failed: %s", exc)
    if policy_block:
        prompt += f"\n\n{policy_block}"
    try:
        result = tracked_invoke(bound, prompt, task="pr-text")
        parsed = _parse_pr_text(str(getattr(result, "content", "") or ""), dashboard, template)
    except (CostCapExceeded, BrainError):
        raise
    except Exception as exc:  # noqa: BLE001 - PR copy never breaks delivery
        log.warning("PR copy generation failed for %s: %s", package, exc)
        return None
    if parsed is None:
        log.debug("PR copy generation unparseable for %s", package)
        return None
    return parsed
