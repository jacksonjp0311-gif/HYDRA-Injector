# HYDRA Injector

**Governed injection for fields, artifacts, and agent-authored code.**

HYDRA Injector is a Python operator toolkit built from the HYDRA v1.4 theory: every injection must be anchored, bounded, retracted against unsafe scope, sealed into an auditable artifact, and checked for drift.

It has two connected modes:

| Mode | What it does |
| --- | --- |
| **Residual Field Injection** | Runs the HYDRA `anchor -> inject -> retract -> seal` operator over admissible masked scalar fields. |
| **Agent Codeweave** | Lets agents propose code insertions into explicit file markers, producing reviewable diffs by default. |

HYDRA Injector is not an exploit tool and does not execute injected code. It is a defensive, review-first injection layer for controlled experiments, agent systems, and governed artifact evolution.

```text
anchor -> inject -> retract -> seal -> report
```

## Why This Matters

Modern agent systems are starting to write code, modify artifacts, maintain memory, and evolve repositories. That creates a hard problem:

> How do you let an agent inject useful structure without letting it drift, overreach, erase context, or smuggle unsafe behavior?

HYDRA Injector answers by making injection explicit and bounded:

- anchor the target,
- inject only into an admissible region,
- retract unsafe or excessive scope,
- seal the result as metrics, a diff, or an archive-gated artifact,
- preserve non-claim boundaries.

The core philosophy is simple:

```text
No anchor, no injection.
No boundary, no promotion.
No seal, no trust.
```

## Install

```powershell
git clone <repo-url>
cd hydra-injector
python -m pip install -e .[dev]
```

For the local workspace used during development:

```powershell
cd "$env:USERPROFILE\OneDrive\Desktop\hydra-injector"
python -m pip install -e .[dev]
```

## Quick Start

Run the residual-field demo:

```powershell
hydra-inject demo
```

Run a HYDRA spec:

```powershell
hydra-inject run examples/demo_spec.json
```

Return machine-readable JSON:

```powershell
hydra-inject run examples/demo_spec.json --format json
```

Test perturbation robustness:

```powershell
hydra-inject robustness examples/demo_spec.json --trials 12 --noise-scale 0.03
```

Generate a starter field spec:

```powershell
hydra-inject scaffold --size 9
```

## Agent Codeweave

Codeweave is the agent-code injection layer. Agents can propose edits, but HYDRA forces them through explicit anchors and reviewable patches.

```text
target file + marker + code block
  -> path checks
  -> extension checks
  -> size checks
  -> forbidden-pattern checks
  -> unified diff
  -> optional explicit apply
```

Plan an injection as a diff:

```powershell
hydra-inject code-plan examples/code_injection_spec.json
```

Return structured JSON:

```powershell
hydra-inject code-plan examples/code_injection_spec.json --format json
```

Verify a codeweave spec for CI:

```powershell
hydra-inject code-verify examples/code_injection_spec.json
```

Plan a multi-injection bundle:

```powershell
hydra-inject code-bundle examples/code_bundle_spec.json --format report
```

Record a session ledger:

```powershell
hydra-inject code-plan examples/code_injection_spec.json --ledger reports/hydra_sessions.jsonl
```

List policy profiles:

```powershell
hydra-inject code-profiles
```

Discover injection markers:

```powershell
hydra-inject markers .
hydra-inject markers . --slots-only
```

Apply and run tests:

```powershell
hydra-inject code-apply examples/code_injection_spec.json --test "python -m pytest"
hydra-inject code-apply examples/code_injection_spec.json --test "python -m pytest" --rollback-on-test-fail
```

Every admissible plan includes a rollback diff. Review reports include both the forward patch and the rollback patch so a human or agent can see how to unwind the change before applying it.

Rollback an applied session record:

```powershell
hydra-inject code-rollback reports/session.json
```

Render an HTML review report:

```powershell
hydra-inject code-bundle examples/code_bundle_spec.json --format html
```

Apply only after review:

```powershell
hydra-inject code-apply examples/code_injection_spec.json
```

Generate a starter codeweave spec:

```powershell
hydra-inject code-scaffold --target-file src/app.py --marker "# HYDRA-INJECT:slot"
```

Codeweave currently blocks:

- path escapes outside the configured root,
- disallowed file extensions,
- oversized snippets,
- `eval(...)`,
- `exec(...)`,
- `os.system(...)`,
- direct `subprocess.` calls,
- pipe-to-shell payloads.

The default workflow is diff-only. Nothing is written unless `code-apply` is used.

Codeweave profiles:

| Profile | Best for |
| --- | --- |
| `strict` | Small, review-heavy code injections. |
| `library` | Python package/library edits. |
| `app` | Application files across Python, JS/TS, CSS, and HTML. |
| `docs` | Documentation-only injection. |
| `experimental` | Larger local experiments that still require anchors. |

## Residual Field Operator

HYDRA uses the ordered composition:

```text
H = Seal o Retract o Inject o Anchor
```

| Stage | Purpose |
| --- | --- |
| **Anchor** | Fix the admissible masked domain. |
| **Inject** | Load a precursor field under volume normalization. |
| **Retract** | Remove controlled bulk amplitude without erasing the residual. |
| **Seal** | Stabilize through constrained local smoothing. |
| **Report** | Emit boundedness, curvature, omega, mass, and nontriviality metrics. |

The stage order is locked. Reordering it changes the operator.

## Metrics

| Metric | Meaning |
| --- | --- |
| `mass` | Absolute residual mass inside the admissible mask. |
| `mean` | Mean residual value inside the mask. |
| `std` | Residual spread inside the mask. |
| `curvature_rms` | RMS discrete Laplacian over the admissible domain. |
| `omega` | Stability proxy: `1 / (1 + abs(curvature_rms))`. |
| `nontriviality` | Guard against trivial smoothing collapse. |
| `bounded` | Whether residual values remain finite. |

## Spec Examples

Field spec:

```json
{
  "mask": [[0, 1, 0], [1, 1, 1], [0, 1, 0]],
  "field": [[0.0, 0.2, 0.0], [0.2, 1.0, 0.2], [0.0, 0.2, 0.0]],
  "config": {
    "target_volume": 1.0,
    "retract_fraction": 0.25,
    "pin_strength": 0.35,
    "boundary_band": 1,
    "seal_steps": 8,
    "seal_alpha": 0.35
  },
  "robustness": true
}
```

Codeweave spec:

```json
{
  "root": ".",
  "target_file": "examples/code_target.py",
  "marker": "# HYDRA-INJECT:slot",
  "mode": "after",
  "code": "\n\ndef injected_hook() -> str:\n    return \"bounded injection\"\n",
  "max_bytes": 20000,
  "rationale": "Demonstrate governed agent-authored code insertion into an explicit marker."
}
```

## Shadow-Header Governance

HYDRA v1.4 makes artifact typing part of anti-drift logic. HYDRA Injector implements that as an archive gate:

```powershell
hydra-inject archive-gate examples/demo_spec.json
```

Archive-ready artifacts should state:

- artifact class,
- claim type,
- evidence basis,
- boundary of validity,
- primary drift risk,
- core invariant,
- memory compression anchor,
- evolution gate,
- terminology stability,
- explicit non-claims.

## What Makes It Different

HYDRA Injector combines four layers that are usually separate:

- numerical residual operation,
- perturbation-basin robustness,
- archive/header governance,
- governed agent code weaving.

That lets it support both scientific-style residual experiments and practical agent-code workflows under the same discipline:

```text
bounded target + explicit claim + sealed output
```

## Use Cases

- Let agents propose code safely through marker-bound diffs.
- Build review-first agent patch workflows.
- Test residual-field stability under perturbation.
- Detect trivial smoothing collapse.
- Package operator runs with archive-ready claim boundaries.
- Keep generated artifacts from drifting into unsupported claims.

## Source Lineage

Primary source: [CODEX Delta Phi - HYDRA v1.4](https://gist.github.com/jacksonjp0311-gif/a2495572513a07d53561de83945c4a9a).

The physical or empirical claims are not imported. The reusable engineering theory is:

- anchor the admissible domain,
- inject under normalization,
- retract in a controlled way,
- seal under constraints,
- preserve boundedness and nontriviality,
- test perturbation invariance,
- keep artifacts typed, bounded, and archive-ready.

Supporting references:

- [Projection methods and proximity operators](https://pcombet.math.ncsu.edu/prox.pdf)
- [Weighted graph Laplacian image inpainting](https://ww3.math.ucla.edu/camreport/cam16-61.pdf)
- [scikit-image random walker segmentation](https://scikit-image.org/docs/0.25.x/auto_examples/segmentation/plot_random_walker_segmentation.html)
- [PlantCV distance transform documentation](https://plantcv.readthedocs.io/en/stable/distance_transform/)

## Development

```powershell
python -m pip install -e .[dev]
python -m pytest
hydra-inject run examples/demo_spec.json
hydra-inject code-verify examples/code_injection_spec.json
hydra-inject code-plan examples/code_injection_spec.json
```

## Non-Claim Lock

HYDRA Injector does not claim:

- universal physical validity,
- fluid-mechanics fidelity,
- benchmark reproduction,
- arbitrary discretization stability,
- that smoothness equals structural validity,
- that generated code is automatically correct or safe,
- that header governance replaces mathematical, empirical, or code review validation.

## License

MIT
