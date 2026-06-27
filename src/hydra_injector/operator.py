"""HYDRA anchor-inject-retract-seal operator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np


@dataclass(frozen=True)
class HydraConfig:
    target_volume: float = 1.0
    retract_fraction: float = 0.25
    pin_strength: float = 0.35
    boundary_band: int = 1
    seal_steps: int = 8
    seal_alpha: float = 0.35


@dataclass(frozen=True)
class HydraResult:
    field: np.ndarray
    metrics: dict[str, float]
    stages: dict[str, np.ndarray]
    admissible: bool
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field.tolist(),
            "metrics": self.metrics,
            "admissible": self.admissible,
            "warnings": list(self.warnings),
        }


def hydra_operator(mask: Any, field: Any, config: HydraConfig | None = None) -> HydraResult:
    """Run the ordered HYDRA operator H = S o R o I o A."""

    cfg = config or HydraConfig()
    domain = anchor_domain(mask)
    source = np.asarray(field, dtype=float)
    if source.shape != domain.shape:
        raise ValueError("field and mask must have the same shape")
    injected = inject_field(domain, source, cfg.target_volume)
    pinned = enforce_pinning(injected, domain, cfg.pin_strength, cfg.boundary_band)
    retracted = retract(pinned, domain, cfg.retract_fraction)
    sealed = seal(retracted, domain, cfg.seal_steps, cfg.seal_alpha)
    metrics = residual_metrics(sealed, domain)
    warnings = tuple(_warnings(metrics, cfg))
    return HydraResult(
        field=sealed,
        metrics=metrics,
        stages={
            "anchored_mask": domain.astype(float),
            "injected": injected,
            "pinned": pinned,
            "retracted": retracted,
            "sealed": sealed,
        },
        admissible=not warnings,
        warnings=warnings,
    )


def anchor_domain(mask: Any) -> np.ndarray:
    domain = np.asarray(mask, dtype=bool)
    if domain.ndim != 2:
        raise ValueError("mask must be a 2D array")
    if not domain.any():
        raise ValueError("mask must contain at least one admissible cell")
    return domain


def inject_field(mask: np.ndarray, field: np.ndarray, target_volume: float) -> np.ndarray:
    injected = np.zeros_like(field, dtype=float)
    values = np.where(mask, field, 0.0)
    mass = float(np.sum(np.abs(values[mask])))
    if mass <= 1e-12:
        injected[mask] = target_volume / int(mask.sum())
    else:
        injected[mask] = values[mask] * (target_volume / mass)
    return injected


def enforce_pinning(field: np.ndarray, mask: np.ndarray, pin_strength: float, band_px: int) -> np.ndarray:
    pinned = np.array(field, dtype=float, copy=True)
    band = boundary_band(mask, band_px)
    mean = float(np.mean(pinned[mask]))
    strength = min(max(pin_strength, 0.0), 1.0)
    pinned[band] = (1.0 - strength) * pinned[band] + strength * mean
    pinned[~mask] = 0.0
    return pinned


def retract(field: np.ndarray, mask: np.ndarray, fraction: float) -> np.ndarray:
    fraction = min(max(fraction, 0.0), 1.0)
    out = np.array(field, dtype=float, copy=True)
    mean = float(np.mean(out[mask]))
    out[mask] = out[mask] - fraction * mean
    out[~mask] = 0.0
    return out


def seal(field: np.ndarray, mask: np.ndarray, steps: int, alpha: float) -> np.ndarray:
    alpha = min(max(alpha, 0.0), 1.0)
    out = np.array(field, dtype=float, copy=True)
    for _ in range(max(0, int(steps))):
        avg = neighbor_average(out, mask)
        out[mask] = (1.0 - alpha) * out[mask] + alpha * avg[mask]
        out[~mask] = 0.0
    return out


def residual_metrics(field: np.ndarray, mask: np.ndarray) -> dict[str, float]:
    values = field[mask]
    curvature = laplacian(field)
    curvature_values = curvature[mask]
    curvature_rms = float(np.sqrt(np.mean(curvature_values**2))) if curvature_values.size else 0.0
    omega = 1.0 / (1.0 + abs(curvature_rms))
    mass = float(np.sum(np.abs(values)))
    std = float(np.std(values)) if values.size else 0.0
    nontriviality = min(1.0, std / (abs(float(np.mean(values))) + std + 1e-12)) if values.size else 0.0
    return {
        "mean": float(np.mean(values)) if values.size else 0.0,
        "std": std,
        "mass": mass,
        "curvature_rms": curvature_rms,
        "omega": float(omega),
        "nontriviality": float(nontriviality),
        "bounded": 1.0 if np.all(np.isfinite(values)) else 0.0,
    }


def boundary_band(mask: np.ndarray, width: int) -> np.ndarray:
    if width <= 0:
        return np.zeros_like(mask, dtype=bool)
    eroded = np.array(mask, dtype=bool, copy=True)
    for _ in range(width):
        eroded = eroded & np.roll(eroded, 1, axis=0) & np.roll(eroded, -1, axis=0)
        eroded = eroded & np.roll(eroded, 1, axis=1) & np.roll(eroded, -1, axis=1)
        eroded[0, :] = False
        eroded[-1, :] = False
        eroded[:, 0] = False
        eroded[:, -1] = False
    return mask & ~eroded


def neighbor_average(field: np.ndarray, mask: np.ndarray) -> np.ndarray:
    total = np.zeros_like(field, dtype=float)
    count = np.zeros_like(field, dtype=float)
    for shift, axis in ((1, 0), (-1, 0), (1, 1), (-1, 1)):
        rolled_field = np.roll(field, shift, axis=axis)
        rolled_mask = np.roll(mask, shift, axis=axis)
        if axis == 0 and shift == 1:
            rolled_mask[0, :] = False
        elif axis == 0 and shift == -1:
            rolled_mask[-1, :] = False
        elif axis == 1 and shift == 1:
            rolled_mask[:, 0] = False
        elif axis == 1 and shift == -1:
            rolled_mask[:, -1] = False
        total += np.where(rolled_mask, rolled_field, 0.0)
        count += rolled_mask.astype(float)
    return np.where(count > 0, total / np.maximum(count, 1.0), field)


def laplacian(field: np.ndarray) -> np.ndarray:
    return (
        np.roll(field, 1, axis=0)
        + np.roll(field, -1, axis=0)
        + np.roll(field, 1, axis=1)
        + np.roll(field, -1, axis=1)
        - 4.0 * field
    )


def _warnings(metrics: dict[str, float], cfg: HydraConfig) -> list[str]:
    warnings: list[str] = []
    if metrics["bounded"] < 1.0:
        warnings.append("residual contains non-finite values")
    if metrics["mass"] <= 1e-9:
        warnings.append("residual trivialized to near-zero mass")
    if metrics["nontriviality"] < 0.02:
        warnings.append("residual may be over-smoothed or structurally trivial")
    if cfg.seal_alpha > 0.8:
        warnings.append("seal_alpha is high; smoothness may be mistaken for validity")
    return warnings

