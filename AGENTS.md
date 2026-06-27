# HYDRA Injector Operating Notes

Before promotion:

```powershell
python -m pytest
hydra-inject run examples/demo_spec.json
hydra-inject code-verify examples/code_injection_spec.json
hydra-inject code-bundle examples/code_bundle_spec.json --format report
hydra-inject markers . --format json
hydra-inject robustness examples/demo_spec.json
```

Preserve the core operator order:

```text
anchor -> inject -> retract -> seal
```

Do not weaken the non-claim boundary. HYDRA Injector is a governed residual-field operator, not a universal simulator, not a fluid-mechanics claim, and not proof that smoothness equals validity.
