"""Perturbation and omega-basin robustness checks."""

from __future__ import annotations

from typing import Any

import numpy as np

from hydra_injector.operator import HydraConfig, hydra_operator


def perturbation_sweep(
    mask: Any,
    field: Any,
    config: HydraConfig | None = None,
    *,
    trials: int = 8,
    noise_scale: float = 0.03,
    seed: int = 17,
) -> dict[str, float]:
    rng = np.random.default_rng(seed)
    base_field = np.asarray(field, dtype=float)
    omegas: list[float] = []
    masses: list[float] = []
    for _ in range(max(1, trials)):
        perturbed = base_field + rng.normal(0.0, noise_scale, size=base_field.shape)
        result = hydra_operator(mask, perturbed, config)
        omegas.append(result.metrics["omega"])
        masses.append(result.metrics["mass"])
    omega_mean = float(np.mean(omegas))
    omega_std = float(np.std(omegas))
    omega_cv = float(omega_std / (omega_mean + 1e-12))
    mass_mean = float(np.mean(masses))
    return {
        "trials": float(trials),
        "noise_scale": float(noise_scale),
        "omega_mean": omega_mean,
        "omega_std": omega_std,
        "omega_cv": omega_cv,
        "mass_mean": mass_mean,
        "omega_basin_robust": 1.0 if omega_cv <= 0.1 and mass_mean > 1e-9 else 0.0,
    }

