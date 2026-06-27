from hydra_injector import HydraConfig, archive_gate, hydra_operator, perturbation_sweep


def test_hydra_operator_returns_bounded_residual():
    spec = _spec()
    result = hydra_operator(spec["mask"], spec["field"], HydraConfig(seal_steps=3))

    assert result.metrics["bounded"] == 1.0
    assert result.metrics["mass"] > 0
    assert 0 < result.metrics["omega"] <= 1


def test_perturbation_sweep_reports_omega_basin_status():
    spec = _spec()
    result = perturbation_sweep(spec["mask"], spec["field"], trials=3, noise_scale=0.01)

    assert result["trials"] == 3.0
    assert result["omega_mean"] > 0
    assert result["omega_cv"] >= 0


def test_archive_gate_requires_shadow_header_fields():
    gate = archive_gate({"title": "x", "non_claims": "not universal and not validated"})

    assert gate["archive_ready"] is False
    assert "version" in gate["missing_fields"]


def _spec():
    return {
        "mask": [[0, 1, 0], [1, 1, 1], [0, 1, 0]],
        "field": [[0.0, 0.2, 0.0], [0.2, 1.0, 0.2], [0.0, 0.2, 0.0]],
    }

