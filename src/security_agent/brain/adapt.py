"""Model-backed adapt hook for patch generation (follow-up #3, FR-15).

Native tool_calls only (D1): the model proposes file edits through one
host-executed tool; the host validates every path, applies the edit,
and computes changed_files from the real diff rather than trusting the
model. No probe pass or a disabled flag means the null hook stays in
charge (D2) — there is no chat-only fallback path.
"""

import logging
from pathlib import Path

from langchain_core.tools import tool

log = logging.getLogger(__name__)

_MAX_CONTEXT_FILES = 3
_MAX_FILE_CHARS = 3000
_MAX_PROMPT_CHARS = 12000
_SKIP_PARTS = {"node_modules", ".git", "__pycache__", ".pip-deps"}
_TEXT_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".json", ".toml", ".txt"}


@tool
def apply_file_edit(file_path: str, new_content: str) -> str:
    """Replace the full content of one in-repo file with new_content."""
    return "queued"  # host executes the call; see make_model_adapt


def _context_files(workdir: Path, package: str) -> list[tuple[str, str]]:
    """Bounded, secret-free context: files mentioning the package first."""
    picked: list[tuple[str, str]] = []
    try:
        paths = sorted(
            p
            for p in workdir.rglob("*")
            if p.is_file()
            and p.suffix in _TEXT_SUFFIXES
            and not any(part in _SKIP_PARTS for part in p.parts)
            and ".env" not in p.name
            and p.stat().st_size <= 100_000
        )
    except OSError:
        return picked
    ranked = sorted(paths, key=lambda p: (package not in _safe_read(p), str(p)))
    for path in ranked[:_MAX_CONTEXT_FILES]:
        text = _safe_read(path)
        if text:
            picked.append((path.relative_to(workdir).as_posix(), text[:_MAX_FILE_CHARS]))
    return picked


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _resolve_inside(workdir: Path, file_path: str) -> Path:
    from security_agent.worker.patch import PatchError

    root = workdir.resolve()
    target = (root / file_path).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise PatchError(f"adapt edit escapes the workdir: {file_path}") from None
    if any(part in _SKIP_PARTS for part in target.parts):
        raise PatchError(f"adapt edit targets a skipped path: {file_path}")
    return target


def make_model_adapt(model=None, *, probe_ok: bool | None = None):
    """Build an AdaptHook backed by a native-tool-calls chat model."""
    from security_agent.brain import get_chat_model
    from security_agent.worker.patch import AdaptResult, PatchError

    if probe_ok is False:
        raise PatchError("model adapt refused: native tool_calls probe has not passed")

    def adapt(workdir: Path, finding, target: str, failures: list[str]) -> AdaptResult:
        from security_agent.brain import tracked_invoke
        from security_agent.control.cost import CostCapExceeded

        bound = model if model is not None else get_chat_model()
        try:
            if hasattr(bound, "bind_tools"):
                bound = bound.bind_tools([apply_file_edit])
            context = _context_files(workdir, finding.package)
            files_blob = "\n\n".join(f"--- {rel} ---\n{text}" for rel, text in context)
            prompt = (
                f"A dependency was bumped: {finding.package} "
                f"{finding.installed_version} -> {target}. Prior failures: "
                f"{'; '.join(failures)[:2000] or 'none'}. "
                "Call apply_file_edit for each file that must change for the "
                "new version; make no edits if none are needed.\n\n"
                f"{files_blob}"
            )[:_MAX_PROMPT_CHARS]
            result = tracked_invoke(bound, prompt, task="adapt")
        except (PatchError, CostCapExceeded):
            raise
        except Exception as exc:  # noqa: BLE001 - repair loop catches PatchError only
            raise PatchError(f"model adapt failed: {exc}") from exc
        calls = getattr(result, "tool_calls", None) or []
        applied: list[str] = []
        for call in calls:
            if not isinstance(call, dict) or call.get("name") != "apply_file_edit":
                continue
            args = call.get("args") or {}
            file_path, new_content = args.get("file_path"), args.get("new_content")
            if not isinstance(file_path, str) or not isinstance(new_content, str):
                raise PatchError("model adapt returned a malformed edit")
            dest = _resolve_inside(workdir, file_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(new_content)
            applied.append(file_path)
        if not applied:
            return AdaptResult([], notes="model proposed no edits")
        from security_agent.worker.patch import diff_files

        changed, untracked = diff_files(workdir)
        return AdaptResult(
            sorted(set(changed) | set(untracked)), notes=f"model edits: {', '.join(applied)}"
        )

    return adapt


_probe_cache: bool | None = None


def select_adapt():
    """Graph wiring: model adapt only when enabled AND the probe passes."""
    global _probe_cache
    from security_agent.config import get_settings
    from security_agent.worker.patch import null_adapt

    settings = get_settings()
    enabled = getattr(settings, "model_adapt_enabled", False)
    if not enabled:
        return null_adapt
    if _probe_cache is None:
        try:
            from security_agent.brain.probe import run_probe

            _probe_cache = bool(run_probe())
        except Exception as exc:  # noqa: BLE001 - probe failure keeps the null hook
            log.warning("model adapt probe failed, staying on null adapt: %s", exc)
            _probe_cache = False
    if not _probe_cache:
        return null_adapt
    return make_model_adapt(probe_ok=True)
