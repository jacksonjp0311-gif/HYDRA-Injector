from pathlib import Path

from hydra_injector import CodeInjectionSpec, plan_code_injection
from hydra_injector.codeweave import discover_markers, inject_text, parse_marker_metadata, risk_score
from hydra_injector.codeweave import plan_code_bundle, render_review_report, render_review_report_html, rollback_session
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


def test_marker_metadata_rejects_profile_mismatch(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# HYDRA-INJECT:slot name=demo profile=docs\n", encoding="utf-8")
    spec = CodeInjectionSpec(
        root=str(tmp_path),
        target_file="target.py",
        marker="# HYDRA-INJECT:slot name=demo profile=docs",
        name="demo",
        profile="strict",
        code="\ndef x():\n    return 1\n",
        rationale="bounded test injection",
    )

    result = plan_code_injection(spec)

    assert result.admissible is False
    assert any("marker profile mismatch" in warning for warning in result.warnings)


def test_marker_metadata_rejects_name_mismatch(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# HYDRA-INJECT:slot name=actual profile=strict\n", encoding="utf-8")
    spec = CodeInjectionSpec(
        root=str(tmp_path),
        target_file="target.py",
        marker="# HYDRA-INJECT:slot name=actual profile=strict",
        name="expected",
        code="\ndef x():\n    return 1\n",
        rationale="bounded test injection",
    )

    result = plan_code_injection(spec)

    assert result.admissible is False
    assert any("marker name mismatch" in warning for warning in result.warnings)


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


def test_code_bundle_same_file_plans_sequentially(tmp_path: Path):
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

    result = plan_code_bundle(bundle, apply=True)

    text = target.read_text(encoding="utf-8")
    assert result.applied is True
    assert "def a" in text
    assert "def b" in text


def test_example_code_bundle_spec_matches_schema():
    _validate_schema("examples/code_bundle_spec.json", "codeweave_bundle.schema.json")


def test_discover_markers_finds_marker(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# HYDRA-INJECT:slot name=init profile=strict\n", encoding="utf-8")

    markers = discover_markers(tmp_path)

    assert markers[0]["file"] == "target.py"
    assert markers[0]["line"] == 1
    assert markers[0]["slot"] == "slot"
    assert markers[0]["name"] == "init"
    assert markers[0]["is_slot"] is True


def test_risk_score_is_bounded():
    spec = CodeInjectionSpec(
        root=".",
        target_file="target.py",
        marker="# slot",
        code="def x():\n    return 1\n",
        rationale="bounded test injection",
    )

    assert 0 < risk_score(spec) <= 1


def test_parse_marker_metadata_extracts_slot_name_profile():
    metadata = parse_marker_metadata("# HYDRA-INJECT:slot name=init profile=strict")

    assert metadata == {"slot": "slot", "name": "init", "profile": "strict"}


def test_rollback_session_restores_before_text(tmp_path: Path):
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

    rollback = rollback_session(result.to_dict())

    assert rollback["rolled_back"][0]["rolled_back"] is True
    assert target.read_text(encoding="utf-8") == "# slot\n"


def test_apply_rolls_back_on_failed_test_command(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# slot\n", encoding="utf-8")
    spec = CodeInjectionSpec(
        root=str(tmp_path),
        target_file="target.py",
        marker="# slot",
        code="\ndef x():\n    return 1\n",
        rationale="bounded test injection",
    )

    result = plan_code_injection(
        spec,
        apply=True,
        test_command="python -c \"import sys; sys.exit(1)\"",
        rollback_on_test_fail=True,
    )

    assert result.test_passed is False
    assert result.rolled_back is True
    assert target.read_text(encoding="utf-8") == "# slot\n"


def test_html_report_contains_html_shell(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("# slot\n", encoding="utf-8")
    spec = CodeInjectionSpec(
        root=str(tmp_path),
        target_file="target.py",
        marker="# slot",
        code="\ndef x():\n    return 1\n",
        rationale="bounded test injection",
    )
    report = render_review_report_html(plan_code_injection(spec))

    assert "<!doctype html>" in report
    assert "HYDRA Codeweave Review" in report
