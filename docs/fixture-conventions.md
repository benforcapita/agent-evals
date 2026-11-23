# Eval Fixture Conventions (LLD §8)

All evaluation fixtures in `benforcapita/agent-evals` must be safe to store in version control and safe to pass through offline evaluation harnesses. No real secrets, credentials, or raw third-party personal contact details may ever appear in fixtures, suites, transcripts, logs, or Notion.

## 1. Directory Layout

```text
fixtures/
  README.md
  _examples/              # Synthetic scanner/validator examples (owned by T3)
  <suite-slug>/           # Suite-specific fixtures (owned by each suite's ticket)
```

Suite manifests live under `suites/<suite-slug>/` and reference fixtures relative to `fixtures/<suite-slug>/` (or `fixtures/`).

## 2. Placeholder Conventions

Replace sensitive or identifying values with structured placeholders:

| Placeholder | Format | Example |
| --- | --- | --- |
| Secret / credential | `{{SECRET:NAME}}` (`NAME` uppercase `[A-Z][A-Z0-9_]*`) | `{{SECRET:NOTION_TOKEN}}` |
| Email address | `{{EMAIL:label}}` | `{{EMAIL:primary-contact}}` |
| Phone number | `{{PHONE:label}}` | `{{PHONE:office-main}}` |
| Sensitive or private URL | `{{URL:label}}` | `{{URL:internal-webhook}}` |

Valid placeholders are allow-listed by the redaction scanner and will not trigger env-var or high-entropy findings.

## 3. Canary Registry (`EVALCANARY_`)

To test whether a subject leaks confidential fixture content into its output, fixtures may include registered synthetic canary tokens prefixed with `EVALCANARY_` (matching `EVALCANARY_[A-Z0-9_]{4,}`):

- **In fixtures (`ScanMode.FIXTURE`)**: registered `EVALCANARY_*` tokens are allowed and pass `evals validate`. Unregistered `EVALCANARY_*` tokens fail with `unregistered_canary`.
- **In subject output (`ScanMode.OUTPUT`)**: any `EVALCANARY_*` token fails validation with `canary_leak`.
- **Before any external write**: `redact_text` replaces every matched secret or canary with `[REDACTED:{rule}]` (for example, `[REDACTED:canary_leak]`, `[REDACTED:linear_key]`).

Suites can register suite-specific canaries in `suites/<slug>/suite.yaml` under `canary_registry: [...]`.

## 4. Redaction Scanner Rules

The scanner checks all text files in suites and fixtures against:

- **Known key formats**:
  - `openai_key` (`sk-...`, `sk-proj-...`, `sk-svcacct-...`, `sk-admin-...`)
  - `anthropic_key` (`sk-ant-...`)
  - `xai_key` (`xai-...`)
  - `github_token` (`ghp_...`, `gho_...`, `ghu_...`, `ghs_...`, `ghr_...`, `github_pat_...`)
  - `linear_key` (`lin_api_...`)
  - `notion_token` (`secret_...`, `ntn_...`)
  - `slack_token` (`xox*`)
  - `aws_access_key` (`AKIA...`, `ASIA...`)
  - `jwt` (`eyJ... . eyJ... . ...`)
  - `pem_block` (`-----BEGIN ... PRIVATE KEY-----`)
- **High-entropy tokens**: `high_entropy_token` for 24+ character tokens with Shannon entropy `> 4.0`.
- **Denied env var assignments**: `env_var_assignment` for hardcoded values assigned to sensitive env var names (such as `OPENAI_API_KEY`, `NOTION_TOKEN`, `LINEAR_API_KEY`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`).
- **Canaries**: `unregistered_canary` (in fixtures) and `canary_leak` (in output).

Scanner findings report only the rule name and location (`path:line:col`) — never the matched value.

## 5. Validating Fixtures Locally

```bash
# Validate a full suite (manifest, cases, criteria, fixtures, redaction scan)
evals validate --suite <slug>

# Validate a single fixture file or directory
evals validate --fixture fixtures/_examples/clean-fixture.json
evals validate --fixture fixtures/_examples/canary-fixture.json

# Verify a planted fake key fails with exit code 3
evals validate --fixture fixtures/_examples/planted-key-fixture.json

# Verify a canary leaked into subject output fails with exit code 3
evals validate --output fixtures/_examples/canary-output.txt
```
