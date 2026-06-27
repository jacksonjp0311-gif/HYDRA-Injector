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
import subprocess
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
    rollback_diff: str = ""
    risk_score: float = 0.0
    test_command: str = ""
    test_passed: bool | None = None
    test_output: str = ""
    before_text: str = ""
    after_text: str = ""
    rolled_back: bool = False

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
            "rollback_diff": self.rollback_diff,
            "risk_score": self.risk_score,
            "test_command": self.test_command,
            "test_passed": self.test_passed,
            "test_output": self.test_output,
            "before_text": self.before_text,
            "after_text": self.after_text,
            "rolled_back": self.rolled_back,
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
    test_command: str = "",
    rollback_on_test_fail: bool = False,
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
            risk_score=risk_score(spec, 1),
            test_command=test_command,
            test_passed=None,
        )

    original = target.read_text(encoding="utf-8")
    updated = inject_text(original, spec.marker, spec.code, spec.mode)
    result = _result_from_text(spec, target, original, updated, session, test_command)
    test_passed: bool | None = None
    test_output = ""
    rolled_back = False
    if apply and result.diff:
        target.write_text(updated, encoding="utf-8")
        if test_command:
            test_passed, test_output = run_test_command(test_command, root)
            if rollback_on_test_fail and test_passed is False:
                target.write_text(original, encoding="utf-8")
                rolled_back = True
    return _replace_result_runtime(
        result,
        applied=bool(apply and result.diff),
        test_passed=test_passed,
        test_output=test_output,
        rolled_back=rolled_back,
    )


def plan_code_bundle(
    raw: dict[str, Any],
    *,
    apply: bool = False,
    test_command: str = "",
    rollback_on_test_fail: bool = False,
) -> CodeBundleResult:
    entries = raw.get("bundle")
    if not isinstance(entries, list) or not entries:
        raise ValueError("bundle spec requires a non-empty 'bundle' list")
    session = str(raw.get("session_id") or new_session_id(raw))
    root = Path(str(raw.get("root", "."))).resolve()
    virtual_texts: dict[Path, str] = {}
    before_texts: dict[Path, str] = {}
    result_list: list[CodeInjectionResult] = []
    for entry in entries:
        spec = CodeInjectionSpec.from_raw({**raw, **entry})
        target = (Path(spec.root).resolve() / spec.target_file).resolve()
        warnings = _validate_spec(spec, Path(spec.root).resolve(), target)
        if warnings:
            result_list.append(
                CodeInjectionResult(
                    target_file=str(target),
                    admissible=False,
                    applied=False,
                    diff="",
                    warnings=tuple(warnings),
                    metrics=_metrics("", spec.code, 0),
                    session_id=session,
                    rationale=spec.rationale,
                    risk_score=risk_score(spec, len(entries)),
                    test_command=test_command,
                )
            )
            continue
        if target not in virtual_texts:
            before_texts[target] = target.read_text(encoding="utf-8")
            virtual_texts[target] = before_texts[target]
        original = virtual_texts[target]
        updated = inject_text(original, spec.marker, spec.code, spec.mode)
        virtual_texts[target] = updated
        result_list.append(_result_from_text(spec, target, original, updated, session, test_command, file_count=len(entries)))

    if apply and all(result.admissible for result in result_list):
        for target, text in virtual_texts.items():
            target.write_text(text, encoding="utf-8")
        test_passed: bool | None = None
        test_output = ""
        rolled_back = False
        if test_command:
            test_passed, test_output = run_test_command(test_command, root)
            if rollback_on_test_fail and test_passed is False:
                for target, text in before_texts.items():
                    target.write_text(text, encoding="utf-8")
                rolled_back = True
        result_list = [
            _replace_result_runtime(
                result,
                applied=bool(result.diff),
                test_passed=test_passed,
                test_output=test_output,
                rolled_back=rolled_back,
            )
            for result in result_list
        ]
    results = tuple(result_list)
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
        f"**Risk Score:** {max((item.risk_score for item in results), default=0.0):.3f}",
        "",
        "## Targets",
        "",
        "| Target | Admissible | Risk | Injected Bytes | Warnings |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for item in results:
        warnings = "; ".join(item.warnings)
        lines.append(
            f"| `{item.target_file}` | {str(item.admissible).lower()} | {item.risk_score:.3f} | "
            f"{int(item.metrics['injected_bytes'])} | {warnings} |"
        )
    test_results = [item for item in results if item.test_command]
    if test_results:
        lines.extend(["", "## Test Command"])
        for item in test_results:
            lines.append(f"- `{item.test_command}` passed: {str(item.test_passed).lower()}")
    lines.extend(["", "## Diff", "", "```diff", combined_diff.rstrip(), "```"])
    rollback_diff = "\n".join(item.rollback_diff for item in results if item.rollback_diff)
    if rollback_diff:
        lines.extend(["", "## Rollback Diff", "", "```diff", rollback_diff.rstrip(), "```"])
    return "\n".join(lines) + "\n"


def render_review_report_html(result: CodeInjectionResult | CodeBundleResult) -> str:
    text = render_review_report(result)
    escaped = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return (
        "<!doctype html>\n"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>HYDRA Codeweave Review</title>"
        "<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:32px auto;"
        "line-height:1.5;color:#17202a}pre{background:#111827;color:#e5e7eb;padding:16px;"
        "overflow:auto;border-radius:6px}code{background:#f3f4f6;padding:2px 4px;border-radius:4px}"
        "</style></head><body><pre>"
        + escaped
        + "</pre></body></html>\n"
    )


def rollback_session(record: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
    results = record.get("results") if "results" in record else [record]
    if not isinstance(results, list):
        raise ValueError("rollback record must contain a result object or results list")
    rolled_back: list[dict[str, Any]] = []
    for item in results:
        target = Path(str(item["target_file"]))
        before = str(item.get("before_text", ""))
        after = str(item.get("after_text", ""))
        if not before:
            rolled_back.append({"target_file": str(target), "rolled_back": False, "reason": "missing before_text"})
            continue
        current = target.read_text(encoding="utf-8")
        if after and current != after and not force:
            rolled_back.append({"target_file": str(target), "rolled_back": False, "reason": "current file does not match after_text"})
            continue
        target.write_text(before, encoding="utf-8")
        rolled_back.append({"target_file": str(target), "rolled_back": True, "reason": ""})
    return {"rolled_back": rolled_back}


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


def discover_markers(root: str | Path, marker_pattern: str = "HYDRA-INJECT") -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    markers: list[dict[str, Any]] = []
    for path in root_path.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix not in {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".txt", ".js", ".ts", ".tsx", ".jsx", ".css", ".html"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if marker_pattern in line:
                metadata = parse_marker_metadata(line)
                is_slot = is_marker_slot(line)
                markers.append(
                    {
                        "file": str(path.relative_to(root_path)),
                        "line": lineno,
                        "marker": line.strip(),
                        "name": metadata.get("name", ""),
                        "profile": metadata.get("profile", ""),
                        "slot": metadata.get("slot", ""),
                        "is_slot": is_slot,
                    }
                )
    return markers


def is_marker_slot(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(("#", "//", "/*", "<!--")) and "HYDRA-INJECT:" in stripped


def parse_marker_metadata(line: str) -> dict[str, str]:
    text = line.strip()
    metadata: dict[str, str] = {}
    slot = re.search(r"HYDRA-INJECT:([A-Za-z0-9_.:-]+)", text)
    if slot:
        metadata["slot"] = slot.group(1)
    for key, value in re.findall(r"\b(name|profile)=([A-Za-z0-9_.:-]+)", text):
        metadata[key] = value
    return metadata


def risk_score(spec: CodeInjectionSpec, file_count: int = 1) -> float:
    profile_weight = {
        "strict": 0.05,
        "library": 0.12,
        "docs": 0.08,
        "app": 0.2,
        "experimental": 0.35,
    }.get(spec.profile, 0.25)
    ext_weight = 0.05 if Path(spec.target_file).suffix in {".md", ".txt", ".json", ".toml", ".yml", ".yaml"} else 0.15
    size_weight = min(0.35, len(spec.code.encode("utf-8")) / max(spec.max_bytes, 1) * 0.35)
    mode_weight = 0.1 if spec.mode == "replace" else 0.03
    file_weight = min(0.25, max(1, file_count) * 0.04)
    return round(min(1.0, profile_weight + ext_weight + size_weight + mode_weight + file_weight), 3)


def run_test_command(command: str, cwd: str | Path) -> tuple[bool, str]:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        shell=True,
        text=True,
        capture_output=True,
        timeout=120,
    )
    output = (completed.stdout + completed.stderr)[-8000:]
    return completed.returncode == 0, output


def _result_from_text(
    spec: CodeInjectionSpec,
    target: Path,
    original: str,
    updated: str,
    session: str,
    test_command: str,
    file_count: int = 1,
) -> CodeInjectionResult:
    diff = unified_diff(original, updated, str(target))
    return CodeInjectionResult(
        target_file=str(target),
        admissible=True,
        applied=False,
        diff=diff,
        warnings=(),
        metrics=_metrics(original, spec.code, len(diff)),
        session_id=session,
        rationale=spec.rationale,
        rollback_diff=unified_diff(updated, original, str(target)),
        risk_score=risk_score(spec, file_count),
        test_command=test_command,
        test_passed=None,
        test_output="",
        before_text=original,
        after_text=updated,
    )


def _replace_result_runtime(
    result: CodeInjectionResult,
    *,
    applied: bool,
    test_passed: bool | None,
    test_output: str,
    rolled_back: bool,
) -> CodeInjectionResult:
    return CodeInjectionResult(
        target_file=result.target_file,
        admissible=result.admissible,
        applied=applied,
        diff=result.diff,
        warnings=result.warnings,
        metrics=result.metrics,
        session_id=result.session_id,
        rationale=result.rationale,
        rollback_diff=result.rollback_diff,
        risk_score=result.risk_score,
        test_command=result.test_command,
        test_passed=test_passed,
        test_output=test_output,
        before_text=result.before_text,
        after_text=result.after_text,
        rolled_back=rolled_back,
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
