# HYDRA Injector

**A governed anchor-inject-retract-seal operator for admissible masked fields.**

HYDRA Injector turns the HYDRA v1.4 residual-operator theory into a practical Python tool. It is not an adversarial injection utility. It is a controlled field-injection and residual-stabilization harness for testing how a scalar field behaves when it is anchored to an admissible domain, normalized, retracted, sealed, and audited for drift.

```text
mask + precursor field
  -> anchor
  -> inject
  -> retract
  -> seal
  -> residual field + metrics + archive gate
```

## Why It Exists

Many systems mistake smoothness for stability, bounded execution for robustness, and a successful run for a valid claim. HYDRA Injector makes those failure modes explicit.

It answers:

> Did the residual remain bounded, nontrivial, admissible, and qualitatively stable under controlled perturbation?

## Core Operator

HYDRA uses the ordered composition:

```text
H = Seal o Retract o Inject o Anchor
```

| Stage | Meaning |
| --- | --- |
| Anchor | Fix the admissible masked domain. |
| Inject | Load a precursor field into that domain under volume normalization. |
| Retract | Remove controlled bulk amplitude without erasing the residual. |
| Seal | Stabilize the residual through constrained local smoothing. |
| Report | Measure curvature, omega, mass, nontriviality, and boundedness. |

The order is intentionally locked. Reordering the stages changes the operator.

## Install

```powershell
cd "$env:USERPROFILE\OneDrive\Desktop\hydra-injector"
python -m pip install -e .[dev]
```

## Quick Start

Run the demo:

```powershell
hydra-inject demo
```

Run a spec file:

```powershell
hydra-inject run examples/demo_spec.json
```

Return JSON:

```powershell
hydra-inject run examples/demo_spec.json --format json
```

Generate a starter spec:

```powershell
hydra-inject scaffold --size 9
```

Run perturbation robustness:

```powershell
hydra-inject robustness examples/demo_spec.json --trials 12 --noise-scale 0.03
```

Check a shadow-header archive gate:

```powershell
hydra-inject archive-gate examples/demo_spec.json
```

## Agent Code Injection

HYDRA Injector can also let agents inject code, but only as a governed edit workflow. It does not execute injected code. It anchors to an explicit file and marker, checks admissibility, retracts unsafe scope, and seals the proposal as a diff unless `code-apply` is explicitly used.

```text
target file + marker + code block
  -> path / extension / size / pattern checks
  -> unified diff
  -> optional explicit apply
```

Plan an injection:

```powershell
hydra-inject code-plan examples/code_injection_spec.json
```

Return structured JSON:

```powershell
hydra-inject code-plan examples/code_injection_spec.json --format json
```

Apply an admissible injection:

```powershell
hydra-inject code-apply examples/code_injection_spec.json
```

Generate a starter code-injection spec:

```powershell
hydra-inject code-scaffold --target-file src/app.py --marker "# HYDRA-INJECT:slot"
```

The codeweave layer blocks path escapes, disallowed file extensions, oversized snippets, and common dangerous patterns such as `eval`, `exec`, `os.system`, subprocess calls, and pipe-to-shell payloads.

## Output Metrics

| Metric | Meaning |
| --- | --- |
| `mass` | Absolute residual mass inside the admissible mask. |
| `mean` | Mean residual value inside the mask. |
| `std` | Residual spread inside the mask. |
| `curvature_rms` | RMS discrete Laplacian over the admissible domain. |
| `omega` | Stability proxy: `1 / (1 + abs(curvature_rms))`. |
| `nontriviality` | Guard against trivial smoothing collapse. |
| `bounded` | Whether residual values remain finite. |

## What Makes This Different

HYDRA Injector combines three layers that are usually separate:

- a numerical residual operator,
- perturbation-basin robustness checks,
- artifact header governance,
- governed agent code weaving.

That means a run is not treated as valid merely because it executes. It must remain bounded, nontrivial, and recallable under explicit claim boundaries.

## Spec Model

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

## Shadow-Header Governance

HYDRA v1.4 makes artifact typing part of anti-drift logic. This repo implements that as an archive gate. A HYDRA artifact should state:

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
```

## Non-Claim Lock

HYDRA Injector does not claim:

- universal physical validity,
- fluid-mechanics fidelity,
- benchmark reproduction,
- arbitrary discretization stability,
- that smoothness equals structural validity,
- that header governance replaces mathematical or empirical validation.

## License

MIT
