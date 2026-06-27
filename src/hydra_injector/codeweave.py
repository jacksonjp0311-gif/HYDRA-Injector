"""Governed code injection for agent-authored patches.

This module treats code injection as a controlled edit operation:

anchor target -> inject snippet -> retract unsafe scope -> seal patch.
It never executes injected code.
"""

from __future__ import annotations

import difflib
import re
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

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "CodeInjectionSpec":
        return cls(
            target_file=str(raw["target_file"]),
            marker=str(raw["marker"]),
            code=str(raw["code"]),
            mode=str(raw.get("mode", "after")),
            root=str(raw.get("root", ".")),
            allow_extensions=tuple(map(str, raw.get("allow_extensions", cls.allow_extensions))),
            max_bytes=int(raw.get("max_bytes", 20000)),
            forbidden_patterns=tuple(map(str, raw.get("forbidden_patterns", DEFAULT_FORBIDDEN_PATTERNS))),
            rationale=str(raw.get("rationale", "")),
        )


@dataclass(frozen=True)
class CodeInjectionResult:
    target_file: str
    admissible: bool
    applied: bool
    diff: str
    warnings: tuple[str, ...]
    metrics: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_file": self.target_file,
            "admissible": self.admissible,
            "applied": self.applied,
            "diff": self.diff,
            "warnings": list(self.warnings),
            "metrics": self.metrics,
        }


def plan_code_injection(spec: CodeInjectionSpec, *, apply: bool = False) -> CodeInjectionResult:
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
    )


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
