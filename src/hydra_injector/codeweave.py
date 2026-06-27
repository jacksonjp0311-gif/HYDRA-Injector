"""Governed code injection for agent-authored patches.

This module treats code injection as a controlled edit operation:

anchor target -> inject snippet -> retract unsafe scope -> seal patch.
It never executes injected code.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_FORBIDDEN_PATTERNS = (
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"subprocess\.",
    r"os\.system\s*\(",
    r"Invoke-Expression",
    r"curl\s+.*\|\s*(sh|bash|powershell)",
    r"wget\s+.*\|\s*(sh|bash|powershell)",
)


PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "strict": {
        "allow_extensions": (".py", ".md", ".json", ".toml", ".yml", ".yaml", ".txt"),
        "max_bytes": 8000,
        "require_rationale": True,
        "marker_required": True,
    },
    "library": {
        "allow_extensions": (".py", ".md", ".toml", ".yml", ".yaml", ".txt"),
        "max_bytes": 16000,
        "require_rationale": True,
        "marker_required": True,
    },
    "app": {
        "allow_extensions": (".py", ".js", ".ts", ".tsx", ".jsx", ".css", ".html", ".md", ".json", ".toml", ".yml", ".yaml", ".txt"),
        "max_bytes": 24000,
        "require_rationale": True,
        "marker_required": True,
    },
    "docs": {
        "allow_extensions": (".md", ".txt", ".rst"),
        "max_bytes": 32000,
        "require_rationale": False,
        "marker_required": True,
    },
    "experimental": {
        "allow_extensions": (".py", ".js", ".ts", ".tsx", ".jsx", ".css", ".html", ".md", ".json", ".toml", ".yml", ".yaml", ".txt"),
        "max_bytes": 50000,
        "require_rationale": False,
        "marker_required": True,
    },
}


@dataclass(frozen=True)
class CodeInjectionSpec:
    target_file: str
    marker: str
    code: str
    mode: str = "after"
    root: str = "."
    allow_extensions: tuple[str, ...] = (".py", ".md", ".json", ".toml", ".yml", ".yaml", ".txt")
    max_bytes: int = 20000
    forbidden_patterns: tuple[str, ...] = field(default_factory=lambda: DEFAULT_FORBIDDEN_PATTERNS)
    rationale: str = ""
    profile: str = "strict"

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "CodeInjectionSpec":
        profile = str(raw.get("profile", "strict"))
        defaults = PROFILE_DEFAULTS.get(profile, PROFILE_DEFAULTS["strict"])
        return cls(
            target_file=str(raw["target_file"]),
            marker=str(raw["marker"]),
            code=str(raw["code"]),
            mode=str(raw.get("mode", "after")),
            root=str(raw.get("root", ".")),
            allow_extensions=tuple(map(str, raw.get("allow_extensions", defaults["allow_extensions"]))),
            max_bytes=int(raw.get("max_bytes", defaults["max_bytes"])),
            forbidden_patterns=tuple(map(str, raw.get("forbidden_patterns", DEFAULT_FORBIDDEN_PATTERNS))),
            rationale=str(raw.get("rationale", "")),
            profile=profile,
        )


@dataclass(frozen=True)
class CodeInjectionResult:
    target_file: str
    admissible: bool
    applied: bool
    diff: str
    warnings: tuple[str, ...]
    metrics: dict[str, float]
    session_id: str = ""
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_file": self.target_file,
            "admissible": self.admissible,
            "applied": self.applied,
            "diff": self.diff,
            "warnings": list(self.warnings),
            "metrics": self.metrics,
            "session_id": self.session_id,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class CodeBundleResult:
    session_id: str
    admissible: bool
    applied: bool
    results: tuple[CodeInjectionResult, ...]
    combined_diff: str
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "admissible": self.admissible,
            "applied": self.applied,
            "results": [result.to_dict() for result in self.results],
            "combined_diff": self.combined_diff,
            "warnings": list(self.warnings),
        }


def plan_code_injection(
    spec: CodeInjectionSpec,
    *,
    apply: bool = False,
    session_id: str | None = None,
) -> CodeInjectionResult:
    session = session_id or new_session_id(spec)
    root = Path(spec.root).resolve()
    target = (root / spec.target_file).resolve()
    warnings = _validate_spec(spec, root, target)
    if warnings:
        return CodeInjectionResult(
            target_file=str(target),
            admissible=False,
            applied=False,
            diff="",
            warnings=tuple(warnings),
            metrics=_metrics("", spec.code, 0),
            session_id=session,
            rationale=spec.rationale,
        )

    original = target.read_text(encoding="utf-8")
    updated = inject_text(original, spec.marker, spec.code, spec.mode)
    diff = unified_diff(original, updated, str(target))
    if apply and diff:
        target.write_text(updated, encoding="utf-8")
    return CodeInjectionResult(
        target_file=str(target),
        admissible=True,
        applied=bool(apply and diff),
        diff=diff,
        warnings=(),
        metrics=_metrics(original, spec.code, len(diff)),
        session_id=session,
        rationale=spec.rationale,
    )


def plan_code_bundle(raw: dict[str, Any], *, apply: bool = False) -> CodeBundleResult:
    entries = raw.get("bundle")
    if not isinstance(entries, list) or not entries:
        raise ValueError("bundle spec requires a non-empty 'bundle' list")
    session = str(raw.get("session_id") or new_session_id(raw))
    results = tuple(
        plan_code_injection(CodeInjectionSpec.from_raw({**raw, **entry}), apply=apply, session_id=session)
        for entry in entries
    )
    combined_diff = "\n".join(result.diff for result in results if result.diff)
    warnings = tuple(warning for result in results for warning in result.warnings)
    return CodeBundleResult(
        session_id=session,
        admissible=all(result.admissible for result in results),
        applied=all(result.applied for result in results if result.diff),
        results=results,
        combined_diff=combined_diff,
        warnings=warnings,
    )


def write_session_ledger(result: CodeInjectionResult | CodeBundleResult, ledger_path: str | Path) -> Path:
    path = Path(ledger_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    payload["recorded_at_unix"] = time.time()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return path


def render_review_report(result: CodeInjectionResult | CodeBundleResult) -> str:
    if isinstance(result, CodeInjectionResult):
        results = [result]
        session_id = result.session_id
        admissible = result.admissible
        applied = result.applied
        combined_diff = result.diff
    else:
        results = list(result.results)
        session_id = result.session_id
        admissible = result.admissible
        applied = result.applied
        combined_diff = result.combined_diff
    lines = [
        "# HYDRA Codeweave Review",
        "",
        f"**Session:** `{session_id}`",
        f"**Admissible:** {str(admissible).lower()}",
        f"**Applied:** {str(applied).lower()}",
        "",
        "## Targets",
        "",
        "| Target | Admissible | Injected Bytes | Warnings |",
        "| --- | --- | ---: | --- |",
    ]
    for item in results:
        warnings = "; ".join(item.warnings)
        lines.append(
            f"| `{item.target_file}` | {str(item.admissible).lower()} | "
            f"{int(item.metrics['injected_bytes'])} | {warnings} |"
        )
    lines.extend(["", "## Diff", "", "```diff", combined_diff.rstrip(), "```"])
    return "\n".join(lines) + "\n"


def new_session_id(seed: Any) -> str:
    payload = json.dumps(seed, sort_keys=True, default=str) + str(time.time_ns())
    return "hydra-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def inject_text(original: str, marker: str, code: str, mode: str) -> str:
    if marker not in original:
        raise ValueError("marker not found in target file")
    if mode not in {"before", "after", "replace"}:
        raise ValueError("mode must be one of: before, after, replace")
    if mode == "replace":
        return original.replace(marker, code, 1)
    insertion = code.strip("\n") + "\n"
    if mode == "before":
        return original.replace(marker, insertion + marker, 1)
    if marker + "\n" in original:
        return original.replace(marker + "\n", marker + "\n" + insertion, 1)
    return original.replace(marker, marker + "\n" + insertion, 1)


def unified_diff(original: str, updated: str, target_name: str) -> str:
    if original == updated:
        return ""
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"{target_name}:before",
            tofile=f"{target_name}:after",
        )
    )


def _validate_spec(spec: CodeInjectionSpec, root: Path, target: Path) -> list[str]:
    warnings: list[str] = []
    try:
        target.relative_to(root)
    except ValueError:
        warnings.append("target file escapes configured root")
    if target.suffix not in spec.allow_extensions:
        warnings.append(f"extension {target.suffix!r} is not allowed")
    if not target.exists():
        warnings.append("target file does not exist")
    if len(spec.code.encode("utf-8")) > spec.max_bytes:
        warnings.append("code exceeds max_bytes")
    if not spec.marker:
        warnings.append("marker is required")
    profile = PROFILE_DEFAULTS.get(spec.profile, PROFILE_DEFAULTS["strict"])
    if profile["require_rationale"] and not spec.rationale.strip():
        warnings.append(f"profile {spec.profile!r} requires rationale")
    for pattern in spec.forbidden_patterns:
        if re.search(pattern, spec.code, flags=re.IGNORECASE | re.MULTILINE):
            warnings.append(f"forbidden pattern matched: {pattern}")
    return warnings


def _metrics(original: str, code: str, diff_len: int) -> dict[str, float]:
    return {
        "original_bytes": float(len(original.encode("utf-8"))),
        "injected_bytes": float(len(code.encode("utf-8"))),
        "diff_bytes": float(diff_len),
        "injected_lines": float(len(code.splitlines())),
    }
