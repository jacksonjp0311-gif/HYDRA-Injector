"""Command-line interface for HYDRA Injector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from hydra_injector.governance import archive_gate
from hydra_injector.operator import HydraConfig, hydra_operator
from hydra_injector.robustness import perturbation_sweep


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hydra-inject",
        description="Run governed anchor-inject-retract-seal residual injection over masked fields.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run a HYDRA spec JSON file.")
    run.add_argument("spec_file")
    run.add_argument("--format", choices=("json", "markdown"), default="markdown")
    run.add_argument("--output", type=Path, default=None)

    demo = sub.add_parser("demo", help="Run the bundled demo spec.")
    demo.add_argument("--format", choices=("json", "markdown"), default="markdown")

    scaffold = sub.add_parser("scaffold", help="Print a starter HYDRA spec.")
    scaffold.add_argument("--size", type=int, default=7)

    robust = sub.add_parser("robustness", help="Run perturbation robustness on a HYDRA spec.")
    robust.add_argument("spec_file")
    robust.add_argument("--trials", type=int, default=8)
    robust.add_argument("--noise-scale", type=float, default=0.03)
    robust.add_argument("--seed", type=int, default=17)

    header = sub.add_parser("archive-gate", help="Validate a shadow-header JSON object.")
    header.add_argument("header_file")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scaffold":
            print(json.dumps(_scaffold(args.size), indent=2))
            return 0
        if args.command == "demo":
            payload = _run_spec(_demo_spec())
            _emit(payload, args.format, None)
            return 0
        if args.command == "run":
            spec = json.loads(Path(args.spec_file).read_text(encoding="utf-8"))
            payload = _run_spec(spec)
            _emit(payload, args.format, args.output)
            return 0
        if args.command == "robustness":
            spec = json.loads(Path(args.spec_file).read_text(encoding="utf-8"))
            cfg = _config(spec.get("config", {}))
            payload = perturbation_sweep(
                spec["mask"],
                spec["field"],
                cfg,
                trials=args.trials,
                noise_scale=args.noise_scale,
                seed=args.seed,
            )
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        if args.command == "archive-gate":
            raw = json.loads(Path(args.header_file).read_text(encoding="utf-8"))
            header = raw.get("header", raw) if isinstance(raw, dict) else raw
            print(json.dumps(archive_gate(header), indent=2, sort_keys=True))
            return 0
        return 1
    except Exception as exc:  # noqa: BLE001 - CLI should return clean operator errors.
        print(f"hydra-inject: {exc}", file=sys.stderr)
        return 1


def _run_spec(spec: dict[str, object]) -> dict[str, object]:
    cfg = _config(spec.get("config", {}))
    result = hydra_operator(spec["mask"], spec["field"], cfg)
    payload = result.to_dict()
    if "header" in spec:
        payload["archive_gate"] = archive_gate(spec["header"])
    if bool(spec.get("robustness", False)):
        payload["robustness"] = perturbation_sweep(spec["mask"], spec["field"], cfg)
    return payload


def _config(raw: object) -> HydraConfig:
    raw = raw if isinstance(raw, dict) else {}
    return HydraConfig(
        target_volume=float(raw.get("target_volume", 1.0)),
        retract_fraction=float(raw.get("retract_fraction", 0.25)),
        pin_strength=float(raw.get("pin_strength", 0.35)),
        boundary_band=int(raw.get("boundary_band", 1)),
        seal_steps=int(raw.get("seal_steps", 8)),
        seal_alpha=float(raw.get("seal_alpha", 0.35)),
    )


def _emit(payload: dict[str, object], fmt: str, output: Path | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) if fmt == "json" else _markdown(payload)
    if output:
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


def _markdown(payload: dict[str, object]) -> str:
    metrics = payload["metrics"]
    lines = [
        "# HYDRA Injection Report",
        "",
        f"**Admissible:** {str(payload['admissible']).lower()}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | --- |",
    ]
    for key, value in sorted(metrics.items()):
        lines.append(f"| {key} | {float(value):.6f} |")
    warnings = payload.get("warnings", [])
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {warning}" for warning in warnings)
    if "archive_gate" in payload:
        gate = payload["archive_gate"]
        lines.extend(["", "## Archive Gate"])
        lines.append(f"- archive_ready: {str(gate['archive_ready']).lower()}")
        for action in gate.get("required_actions", []):
            lines.append(f"- {action}")
    return "\n".join(lines)


def _demo_spec() -> dict[str, object]:
    return _scaffold(7)


def _scaffold(size: int) -> dict[str, object]:
    size = max(3, int(size))
    yy, xx = np.mgrid[:size, :size]
    center = (size - 1) / 2
    radius = max(1.0, size / 2 - 1)
    mask = ((xx - center) ** 2 + (yy - center) ** 2 <= radius**2).astype(int)
    field = np.exp(-(((xx - center) ** 2 + (yy - center) ** 2) / max(radius, 1.0))).round(6)
    return {
        "mask": mask.tolist(),
        "field": field.tolist(),
        "config": {
            "target_volume": 1.0,
            "retract_fraction": 0.25,
            "pin_strength": 0.35,
            "boundary_band": 1,
            "seal_steps": 8,
            "seal_alpha": 0.35,
        },
        "robustness": True,
        "header": {
            "title": "HYDRA residual injection artifact",
            "version": "v0.1",
            "author": "James Paul Jackson",
            "date": "2026-06-27",
            "status": "operator scaffold",
            "artifact_class": "software bridge / architecture scaffold",
            "claim_type": "bounded operator execution claim",
            "evidence_basis": "local generated demo",
            "boundary_of_validity": "2D masked scalar fields",
            "primary_drift_risk": "smoothness mistaken for validity",
            "core_invariant": "anchor, inject, retract, seal, and report bounded residual metrics",
            "memory_compression_anchor": "HYDRA residual execution remains valid only while boundedness and nontriviality remain visible",
            "cross_canon_alignment": "projection, inpainting, constrained smoothing",
            "source_extraction": "HYDRA v1.4 gist",
            "empirical_confidence_badge": "demo only, not external validation",
            "purpose": "generate a governed residual injection run",
            "evolution_gate": "additive changes only",
            "terminology_stability": "do not rename anchor, inject, retract, seal",
            "non_claims": "not universal, not physically validated, not a substitute for empirical validation",
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
