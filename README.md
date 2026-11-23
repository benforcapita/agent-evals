# agent-evals

Evaluation runner, redaction scanner, and validation tooling for core shared skills and the AgentReady report factory.

## Requirements

- Python 3.12+

## Installation

### Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install --no-deps -e .
```

### Box install (LLD §1)

Install into `/workspace/shared/evals/` with wrapper `/workspace/shared/evals/bin/evals`:

```bash
python3 -m venv /workspace/shared/evals/.venv
/workspace/shared/evals/.venv/bin/pip install -r requirements.lock
/workspace/shared/evals/.venv/bin/pip install --no-deps -e /workspace/shared/evals
mkdir -p /workspace/shared/evals/bin
cat <<'EOF' > /workspace/shared/evals/bin/evals
#!/usr/bin/env bash
exec /workspace/shared/evals/.venv/bin/evals "$@"
EOF
chmod +x /workspace/shared/evals/bin/evals
```

## CLI Usage

### Validate a suite

Checks suite, case, criteria, and fixture schemas plus redaction scanning (no model calls, no Notion writes):

```bash
evals validate --suite <slug>
evals validate --suite <slug> --root /path/to/repo --json
```

### Validate a fixture or sample output

```bash
# Fixture mode: placeholders and registered EVALCANARY_* tokens allowed; secrets fail
evals validate --fixture fixtures/_examples/canary-fixture.json

# Output mode: any EVALCANARY_* token or secret fails
evals validate --output fixtures/_examples/canary-output.txt
```

### Scan or redact files

```bash
evals scan path/to/file --mode fixture
evals scan path/to/output.txt --mode output
evals scan path/to/file --mode output --redact
```

### Exit codes

- `0`: valid / clean
- `1`: schema or structural validation error
- `2`: CLI usage or missing target error
- `3`: redaction finding (secret or canary leak detected)

## Running Tests

```bash
pytest
ruff check src tests
```

## Fixture Conventions

See [docs/fixture-conventions.md](docs/fixture-conventions.md) and [fixtures/README.md](fixtures/README.md).
