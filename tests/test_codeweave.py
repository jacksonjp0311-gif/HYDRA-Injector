from pathlib import Path

from hydra_injector import CodeInjectionSpec, plan_code_injection
from hydra_injector.codeweave import inject_text
from hydra_injector.codeweave import plan_code_bundle, render_review_report
from hydra_injector.cli import _validate_schema


def test_inject_text_after_marker():
    original = "a\n# slot\nb\n"
    updated = inject_text(original, "# slot", "\nX\n", "after")

    assert "# slot\nX\nb" in updated


def test_plan_code_injection_generates_diff(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# slot\n", encoding="utf-8")
    spec = CodeInjectionSpec(
        root=str(tmp_path),
        target_file="target.py",
        marker="# slot",
        code="\ndef x():\n    return 1\n",
        rationale="bounded test injection",
    )

    result = plan_code_injection(spec)

    assert result.admissible is True
    assert result.applied is False
    assert "+def x():" in result.diff


def test_code_injection_blocks_forbidden_pattern(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# slot\n", encoding="utf-8")
    spec = CodeInjectionSpec(
        root=str(tmp_path),
        target_file="target.py",
        marker="# slot",
        code="\neval('1+1')\n",
    )

    result = plan_code_injection(spec)

    assert result.admissible is False
    assert any("forbidden pattern" in warning for warning in result.warnings)


def test_code_apply_writes_when_admissible(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# slot\n", encoding="utf-8")
    spec = CodeInjectionSpec(
        root=str(tmp_path),
        target_file="target.py",
        marker="# slot",
        code="\ndef x():\n    return 1\n",
        rationale="bounded test injection",
    )

    result = plan_code_injection(spec, apply=True)

    assert result.applied is True
    assert "def x" in target.read_text(encoding="utf-8")


def test_example_codeweave_spec_matches_schema():
    _validate_schema("examples/code_injection_spec.json", "codeweave_spec.schema.json")


def test_code_bundle_generates_combined_report(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# a\n# b\n", encoding="utf-8")
    bundle = {
        "root": str(tmp_path),
        "profile": "strict",
        "rationale": "bounded multi-file test",
        "bundle": [
            {"target_file": "target.py", "marker": "# a", "code": "\ndef a():\n    return 1\n"},
            {"target_file": "target.py", "marker": "# b", "code": "\ndef b():\n    return 2\n"},
        ],
    }

    result = plan_code_bundle(bundle)
    report = render_review_report(result)

    assert result.admissible is True
    assert "def a" in result.combined_diff
    assert "HYDRA Codeweave Review" in report


def test_example_code_bundle_spec_matches_schema():
    _validate_schema("examples/code_bundle_spec.json", "codeweave_bundle.schema.json")
