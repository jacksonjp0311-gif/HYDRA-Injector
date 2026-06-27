# HYDRA Injector Release Checklist

Use this checklist before tagging or publishing.

## Local Gate

```powershell
python -m pip install -e .[dev]
python -m pytest
hydra-inject run examples/demo_spec.json
hydra-inject robustness examples/demo_spec.json
hydra-inject code-verify examples/code_injection_spec.json
hydra-inject code-apply examples/code_injection_spec.json --dry-run
hydra-inject code-bundle examples/code_bundle_spec.json --format html > reports/hydra-codeweave-review.html
hydra-inject markers . --slots-only --format json
```

## Publish Review

- Confirm the README quick start is current.
- Confirm `CHANGELOG.md` has the release date and behavioral changes.
- Confirm example markers include explicit `name` and `profile` metadata where code injection is demonstrated.
- Confirm no generated review report is committed unless intentionally included as an example artifact.
- Confirm the non-claim lock remains intact.

## Release Notes Seed

HYDRA Injector 0.2.0 promotes Codeweave into a stronger governed agent-code injection workflow: dry-run apply validation, metadata-bound injection markers, structured HTML review reports, rollback-ready session records, and CI coverage for release-critical commands.
