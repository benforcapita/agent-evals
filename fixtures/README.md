# Fixtures

Eval fixtures live in per-suite subdirectories (`fixtures/<suite-slug>/`).

See [docs/fixture-conventions.md](../docs/fixture-conventions.md) for the full rules on placeholders (`{{SECRET:NAME}}`, `{{EMAIL:label}}`, `{{PHONE:label}}`, `{{URL:label}}`), registered `EVALCANARY_` tokens, and redaction scanning.

## Synthetic Examples (`fixtures/_examples/`)

| File | Purpose | Expected `evals validate` result |
| --- | --- | --- |
| `_examples/clean-fixture.json` | Clean fixture using standard placeholders | Exit `0` with `--fixture` |
| `_examples/canary-fixture.json` | Fixture containing registered `EVALCANARY_EXAMPLE_TOKEN_01` | Exit `0` with `--fixture` |
| `_examples/planted-key-fixture.json` | Synthetic planted fake Linear key (no real secret) | Exit `3` (`linear_key`) with `--fixture` |
| `_examples/canary-output.txt` | Sample subject output echoing `EVALCANARY_EXAMPLE_TOKEN_01` | Exit `3` (`canary_leak`) with `--output` |
