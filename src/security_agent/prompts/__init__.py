"""Central prompt templates with strict named substitution.

Prompt text lives in ``templates/<name>.md`` as plain text with
``$placeholder`` markers (``string.Template``; literal braces and JSON
examples need no escaping). Every value a template needs is passed to
[render_prompt](/Users/f3lx/Documents/projects/meta/src/security_agent/prompts/__init__.py)
by name, so injection points stay visible in code while wording stays
editable without touching Python.

Substitution is strict: a missing value raises KeyError immediately
instead of silently shipping a half-filled prompt.
"""

from functools import cache
from importlib.resources import files
from string import Template

_TEMPLATE_DIR = "templates"

PROMPT_NAMES = (
    "adapt",
    "adapt_search_followup",
    "draft_pr",
    "draft_pr_template_block",
    "news_classify",
    "news_relevance",
    "policy_extract",
)


@cache
def _load(name: str) -> Template:
    if name not in PROMPT_NAMES:
        raise ValueError(f"Unknown prompt template: {name!r}; want one of {PROMPT_NAMES}.")
    resource = files(__package__).joinpath(_TEMPLATE_DIR, f"{name}.md")
    return Template(resource.read_text(encoding="utf-8"))


def render_prompt(name: str, /, **values: str) -> str:
    """Render the named prompt template with $placeholder substitution."""
    return _load(name).substitute(values)
