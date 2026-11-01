"""Repository profile for repo-aware news relevance (FR-6).

A profile is what the relevance model is allowed to know about a repo:
the code it actually uses (ecosystems + packages from scanner findings)
and the platforms it can plausibly be deployed to (OS, runtime, cloud,
hosting, container, hardware signals). Deployment signals are *plausible*
targets inferred from ecosystems, well-known SDK packages, and — for
local repos whose checkout is on disk — manifest files such as a
Dockerfile, Compose file, Terraform, Kubernetes manifests, or CI
`runs-on` labels. They are never presented as confirmed facts.

Profiles are derived, never stored: findings are the source of truth, so
a profile can be rebuilt at any time and mixed-version readers/writers
stay safe (the relevance table is additive only).
"""

import re
from pathlib import Path

from sqlalchemy import select

from security_agent.db.models import Finding, Repo
from security_agent.db.session import session_scope

MAX_PACKAGES = 60
MAX_ADVISORIES = 40
_MAX_PROBE_FILES = 300
_MAX_PROBE_READS = 24
_MAX_PROBE_BYTES = 20_000
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "vendor", ".pip-deps"}

# Ecosystem (lowercased, as stored on findings) -> (languages, runtimes).
_ECOSYSTEM_STACK: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "npm": (("javascript", "typescript"), ("nodejs",)),
    "pypi": (("python",), ("python",)),
    "maven": (("java", "kotlin", "scala"), ("jvm", "java")),
    "gradle": (("java", "kotlin"), ("jvm", "java")),
    "nuget": (("csharp", "fsharp"), ("dotnet",)),
    "go": (("go",), ("go",)),
    "crates.io": (("rust",), ("rust",)),
    "cargo": (("rust",), ("rust",)),
    "rubygems": (("ruby",), ("ruby",)),
    "packagist": (("php",), ("php",)),
    "composer": (("php",), ("php",)),
    "hex": (("elixir", "erlang"), ("beam",)),
    "pub": (("dart",), ("dart",)),
    "swiftpm": (("swift",), ("swift",)),
    "cocoapods": (("swift", "objective-c"), ("swift",)),
    "conan": (("c", "cpp"), ()),
    "vcpkg": (("c", "cpp"), ()),
}

# Deployment signal -> keywords matched (word-ish, lowercased) in news text.
# This taxonomy is the shared vocabulary between the profile (which signals
# a repo plausibly has) and the story (which signals it mentions).
PLATFORM_KEYWORDS: dict[str, tuple[str, ...]] = {
    "linux": ("linux", "ubuntu", "debian", "rhel", "red hat", "fedora", "systemd", "kernel"),
    "windows": ("windows server", "windows", "active directory", "iis"),
    "macos": ("macos", "darwin", "apple silicon"),
    "nodejs": ("node.js", "nodejs", "npm", "javascript", "typescript", "deno", "bun"),
    "python": ("python", "pypi", "pip", "cpython", "django", "flask"),
    "jvm": ("java", "jvm", "spring", "kotlin"),
    "dotnet": (".net", "dotnet", "asp.net", "c#", "nuget"),
    "go": ("golang",),
    "rust": ("rust", "cargo"),
    "php": ("php", "laravel", "wordpress"),
    "ruby": ("ruby", "rails", "rubygems"),
    "docker": ("docker", "container image", "oci image", "containerd"),
    "kubernetes": ("kubernetes", "k8s", "helm chart"),
    "aws": ("aws", "amazon web services", "ec2", "amazon s3", "aws lambda"),
    "azure": ("azure", "microsoft azure"),
    "gcp": ("google cloud", "gcp", "gke"),
    "cloudflare": ("cloudflare",),
    "terraform": ("terraform",),
    "arm": ("arm64", "aarch64", "arm chip", "apple silicon"),
    "x86": ("x86", "intel", "amd", "x86_64"),
    "gpu": ("nvidia", "gpu", "cuda"),
}

# Package-name hints: a dependency on a cloud/container SDK makes the
# corresponding platform a plausible deployment target for the repo.
_PACKAGE_SIGNAL_HINTS: tuple[tuple[str, str], ...] = (
    ("@aws-sdk/", "aws"),
    ("aws-sdk", "aws"),
    ("boto3", "aws"),
    ("botocore", "aws"),
    ("@azure/", "azure"),
    ("azure-", "azure"),
    ("google-cloud-", "gcp"),
    ("@google-cloud/", "gcp"),
    ("kubernetes", "kubernetes"),
    ("docker", "docker"),
    ("terraform", "terraform"),
    ("cloudflare", "cloudflare"),
)


def _ecosystem_key(raw: str | None) -> str:
    return (raw or "").strip().lower()


def _probe_local_checkout(root: Path) -> tuple[set[str], list[str]]:
    """Deployment signals + evidence from a local checkout (bounded, read-only)."""
    signals: set[str] = set()
    evidence: list[str] = []
    try:
        candidates = [
            p
            for p in sorted(root.rglob("*"))
            if p.is_file()
            and not any(part in _SKIP_DIRS for part in p.parts)
            and ".env" not in p.name
        ][:_MAX_PROBE_FILES]
    except OSError:
        return signals, evidence
    reads = 0
    for path in candidates:
        rel = path.relative_to(root).as_posix()
        name = path.name.lower()
        low = rel.lower()
        hit: str | None = None
        if name.startswith("dockerfile"):
            signals.update({"docker", "linux"})
            hit = "docker"
        elif name.startswith(("docker-compose", "compose.")) and path.suffix in {".yml", ".yaml"}:
            signals.update({"docker", "linux"})
            hit = "docker"
        elif path.suffix == ".tf":
            signals.add("terraform")
            hit = "terraform"
        elif name == "chart.yaml" or "/k8s/" in low or "/kubernetes/" in low or "/helm/" in low:
            signals.update({"kubernetes", "linux"})
            hit = "kubernetes"
        if hit:
            evidence.append(f"{hit}:{rel}")
        if reads >= _MAX_PROBE_READS:
            continue
        if not (
            low.startswith(".github/workflows/")
            or name in {"dockerfile", "package.json"}
            or path.suffix == ".tf"
        ):
            continue
        try:
            if path.stat().st_size > _MAX_PROBE_BYTES:
                continue
            text = path.read_text(errors="replace")[:_MAX_PROBE_BYTES].lower()
        except OSError:
            continue
        reads += 1
        if "windows" in text:
            signals.add("windows")
            evidence.append(f"windows:{rel}")
        if "ubuntu" in text or "linux" in text:
            signals.add("linux")
        if "macos" in text:
            signals.add("macos")
        for signal, needles in (
            ("aws", ("aws", "amazonaws")),
            ("azure", ("azure",)),
            ("gcp", ("google cloud", "gcp", "gke")),
            ("kubernetes", ("kubernetes", "kubectl", "helm")),
            ("docker", ("docker",)),
        ):
            if any(n in text for n in needles):
                signals.add(signal)
    return signals, sorted(set(evidence))[:20]


def build_repo_profile(repo_id: int) -> dict | None:
    """Derived profile for one repo, or None when the repo is unknown.

    Returns a JSON-friendly dict: repo identity, ecosystems, packages,
    advisory IDs already seen on the repo, languages/runtimes, plausible
    deployment signals with the evidence that produced them, and a
    prompt-ready `summary` string.
    """
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            return None
        name, kind, url, local_path = repo.name, repo.kind, repo.url, repo.local_path
        rows = list(
            db.execute(
                select(Finding.package, Finding.ecosystem, Finding.advisory_id)
                .where(Finding.repo_id == repo_id)
                .order_by(Finding.package, Finding.advisory_id)
            ).all()
        )
    packages = sorted({str(p) for p, _, _ in rows if p})[:MAX_PACKAGES]
    ecosystems = sorted({_ecosystem_key(e) for _, e, _ in rows if _ecosystem_key(e)})
    advisories = sorted({str(a).upper() for _, _, a in rows if a})[:MAX_ADVISORIES]

    languages: set[str] = set()
    runtimes: set[str] = set()
    signals: set[str] = set()
    evidence: list[str] = []
    for eco in ecosystems:
        langs, runs = _ECOSYSTEM_STACK.get(eco, ((), ()))
        languages.update(langs)
        runtimes.update(runs)
        signals.update(runs)
        if runs:
            evidence.append(f"ecosystem:{eco}->{','.join(runs)}")
    # A server-side stack plausibly runs on Linux containers unless there is
    # a specific reason to think otherwise; keep it explicitly "plausible".
    if runtimes:
        signals.add("linux")
    for package in packages:
        low = package.lower()
        for needle, signal in _PACKAGE_SIGNAL_HINTS:
            if needle in low:
                signals.add(signal)
                evidence.append(f"package:{package}->{signal}")
    if local_path:
        try:
            root = Path(local_path)
            if root.is_dir():
                found, found_evidence = _probe_local_checkout(root)
                signals.update(found)
                evidence.extend(found_evidence)
        except OSError:
            pass
    profile = {
        "repo_id": repo_id,
        "repo_name": name,
        "kind": str(getattr(kind, "value", kind)),
        "url": url,
        "ecosystems": ecosystems,
        "packages": packages,
        "advisories": advisories,
        "languages": sorted(languages),
        "runtimes": sorted(runtimes),
        "deployment_signals": sorted(signals),
        "deployment_evidence": sorted(set(evidence))[:30],
    }
    profile["summary"] = profile_summary(profile)
    return profile


def profile_summary(profile: dict) -> str:
    """One prompt-ready paragraph describing the repo (capped, deterministic)."""
    parts = [f"Repository: {profile.get('repo_name') or 'unknown'}"]
    if profile.get("ecosystems"):
        parts.append("Ecosystems: " + ", ".join(profile["ecosystems"][:10]))
    if profile.get("languages"):
        parts.append("Languages: " + ", ".join(profile["languages"][:10]))
    if profile.get("runtimes"):
        parts.append("Runtimes: " + ", ".join(profile["runtimes"][:10]))
    if profile.get("packages"):
        parts.append("Dependencies in use: " + ", ".join(profile["packages"][:40]))
    if profile.get("advisories"):
        parts.append("Advisories already affecting it: " + ", ".join(profile["advisories"][:20]))
    if profile.get("deployment_signals"):
        parts.append(
            "Plausible deployment targets (inferred, not confirmed): "
            + ", ".join(profile["deployment_signals"][:20])
        )
    if len(parts) == 1:
        parts.append("No dependency or deployment signals recorded yet.")
    return ". ".join(parts)[:3000]


def mentioned_platforms(text: str) -> list[str]:
    """Deployment signals whose keywords appear in the given story text."""
    low = f" {(text or '').lower()} "
    found = []
    for signal, keywords in PLATFORM_KEYWORDS.items():
        if any(re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", low) for kw in keywords):
            found.append(signal)
    return sorted(found)
