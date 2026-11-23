"""Unit tests for every LLD §8 redaction rule, placeholders, and canary registry.

All test inputs use programmatically constructed synthetic fake values — never
real credentials.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evals.redaction import (
    ALL_RULE_NAMES,
    CanaryRegistry,
    ScanMode,
    extract_placeholders,
    is_valid_placeholder,
    redact_text,
    scan_text,
    shannon_entropy,
)


def _synthetic_samples() -> list[tuple[str, str, str]]:
    """Return (rule_name, positive_sample, negative_sample) for every LLD §8 rule."""
    # Construct synthetic fake tokens programmatically so no real-looking token literals exist.
    fake_openai = "sk-proj-" + ("AbCdEf1234" * 3)
    fake_anthropic = "sk-ant-" + ("api03FakeTest" * 2)
    fake_xai = "xai-" + ("FakeTokenValue123456" * 2)
    fake_github_classic = "ghp_" + ("FakeGitHubToken01234" * 2)
    fake_github_pat = "github_pat_" + ("FakePatToken0123456789" * 2)
    fake_linear = "lin_api_" + ("FakeLinearKey0123456" * 2)
    fake_notion_secret = "secret_" + ("FakeNotionToken01234567" * 2)
    fake_notion_ntn = "ntn_" + ("FakeNotionToken01234567" * 2)
    fake_slack = "xoxb-" + "000000000000-000000000000-FakeSlackToken000000"
    fake_aws = "AKIA" + "0123456789ABCDEF"
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJmYWtlLXVzZXItMTIzNDUifQ."
        "FakeSignaturePayload0123456789abcd"
    )
    fake_pem = (
        "-----BEGIN " + "PRIVATE KEY-----\n"
        "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA0FakeKeyData\n"
        "-----END " + "PRIVATE KEY-----"
    )
    # 36 unique-ish chars across upper, lower, digits, symbols -> entropy > 4.5
    fake_high_entropy = "aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zC+fI/L"
    fake_env_val = "hardcoded-fake-value-123"

    return [
        ("openai_key", f"token={fake_openai}", "token={{SECRET:OPENAI_API_KEY}}"),
        ("anthropic_key", f"key: {fake_anthropic}", "key: {{SECRET:ANTHROPIC_API_KEY}}"),
        ("xai_key", f"xai={fake_xai}", "xai={{SECRET:XAI_API_KEY}}"),
        ("github_token", f"gh={fake_github_classic}", "gh={{SECRET:GITHUB_TOKEN}}"),
        ("github_token", f"pat={fake_github_pat}", "pat=github_docs_reference"),
        ("linear_key", f"linear={fake_linear}", "linear={{SECRET:LINEAR_API_KEY}}"),
        ("notion_token", f"notion={fake_notion_secret}", "notion={{SECRET:NOTION_TOKEN}}"),
        ("notion_token", f"notion={fake_notion_ntn}", "notion=ntn_short"),
        ("slack_token", f"slack={fake_slack}", "slack={{SECRET:SLACK_BOT_TOKEN}}"),
        ("aws_access_key", f"aws={fake_aws}", "aws=AKIA_SHORT"),
        ("jwt", f"auth: Bearer {fake_jwt}", "auth: Bearer {{SECRET:AUTH_TOKEN}}"),
        ("pem_block", fake_pem, "public documentation about PEM certificates"),
        (
            "high_entropy_token",
            f"blob={fake_high_entropy}",
            "blob=aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "env_var_assignment",
            f"OPENAI_API_KEY={fake_env_val}",
            "OPENAI_API_KEY={{SECRET:OPENAI_API_KEY}}",
        ),
    ]


@pytest.mark.parametrize(("rule_name", "positive", "negative"), _synthetic_samples())
def test_rule_positive_and_negative(rule_name: str, positive: str, negative: str) -> None:
    pos_findings = scan_text(positive, path="sample.txt", mode=ScanMode.FIXTURE)
    assert any(f.rule == rule_name for f in pos_findings), (
        f"Expected rule '{rule_name}' to trigger on positive sample; got {pos_findings}"
    )

    neg_findings = scan_text(negative, path="sample.txt", mode=ScanMode.FIXTURE)
    assert neg_findings == [], (
        f"Expected clean negative sample for '{rule_name}'; got {neg_findings}"
    )


def test_findings_never_leak_matched_secret_value() -> None:
    secret_value = "lin_api_" + ("NeverLeakThisValue987654321" * 1)
    text = f"header\nLINEAR_API_KEY={secret_value}\nfooter\n"
    findings = scan_text(text, path="fixtures/test.env", mode=ScanMode.FIXTURE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "linear_key"
    assert finding.path == "fixtures/test.env"
    assert finding.line == 2
    assert finding.column > 0

    serialized = "\n".join(
        [
            repr(finding),
            str(finding),
            finding.format_line(),
            json.dumps(finding.to_dict()),
        ]
    )
    assert secret_value not in serialized
    assert "NeverLeakThisValue" not in serialized


def test_redact_text_replaces_with_rule_tag() -> None:
    fake_linear = "lin_api_" + ("FakeLinearKey0123456" * 2)
    fake_aws = "AKIA" + "0123456789ABCDEF"
    text = f"a={fake_linear} b={fake_aws} c=EVALCANARY_EXAMPLE_TOKEN_01"

    result = redact_text(text, path="output.txt", mode=ScanMode.OUTPUT)
    assert result.has_findings
    assert fake_linear not in result.redacted_text
    assert fake_aws not in result.redacted_text
    assert "EVALCANARY_EXAMPLE_TOKEN_01" not in result.redacted_text
    assert result.redacted_text == (
        "a=[REDACTED:linear_key] b=[REDACTED:aws_access_key] c=[REDACTED:canary_leak]"
    )
    assert [f.rule for f in result.findings] == ["linear_key", "aws_access_key", "canary_leak"]


def test_canary_allowed_in_fixture_and_fails_in_output() -> None:
    text = "fixture note with EVALCANARY_EXAMPLE_TOKEN_01 inside"

    fixture_findings = scan_text(text, path="fixture.json", mode=ScanMode.FIXTURE)
    assert fixture_findings == []

    output_findings = scan_text(text, path="output.txt", mode=ScanMode.OUTPUT)
    assert len(output_findings) == 1
    assert output_findings[0].rule == "canary_leak"
    assert "EVALCANARY_EXAMPLE_TOKEN_01" not in output_findings[0].format_line()


def test_unregistered_canary_fails_in_fixture_unless_registered() -> None:
    custom = "EVALCANARY_CUSTOM_SUITE_99"
    text = f"note: {custom}"

    default_findings = scan_text(text, path="fixture.json", mode=ScanMode.FIXTURE)
    assert len(default_findings) == 1
    assert default_findings[0].rule == "unregistered_canary"
    assert custom not in default_findings[0].format_line()

    custom_registry = CanaryRegistry().merged_with([custom])
    allowed_findings = scan_text(
        text, path="fixture.json", mode=ScanMode.FIXTURE, registry=custom_registry
    )
    assert allowed_findings == []

    output_findings = scan_text(
        text, path="output.txt", mode=ScanMode.OUTPUT, registry=custom_registry
    )
    assert len(output_findings) == 1
    assert output_findings[0].rule == "canary_leak"


def test_canary_registry_from_file(tmp_path: Path) -> None:
    reg_file = tmp_path / "canaries.yaml"
    reg_file.write_text("canaries:\n  - EVALCANARY_FROM_FILE_01\n", encoding="utf-8")
    registry = CanaryRegistry.from_file(reg_file)
    assert registry.is_registered("EVALCANARY_FROM_FILE_01")
    assert registry.is_registered("EVALCANARY_EXAMPLE_TOKEN_01")


def test_placeholders_validation_and_allowlisting() -> None:
    assert is_valid_placeholder("{{SECRET:NOTION_TOKEN}}")
    assert is_valid_placeholder("{{EMAIL:primary-contact}}")
    assert is_valid_placeholder("{{PHONE:office_1}}")
    assert is_valid_placeholder("{{URL:webhook-endpoint}}")
    assert not is_valid_placeholder("{{SECRET:lowercase_invalid}}")
    assert not is_valid_placeholder("{{OTHER:foo}}")

    sample = (
        '{"NOTION_TOKEN": "{{SECRET:NOTION_TOKEN}}", '
        '"email": "{{EMAIL:owner}}", '
        '"phone": "{{PHONE:desk}}", '
        '"url": "{{URL:portal}}"}'
    )
    placeholders = extract_placeholders(sample)
    assert [(p.kind, p.label) for p in placeholders] == [
        ("SECRET", "NOTION_TOKEN"),
        ("EMAIL", "owner"),
        ("PHONE", "desk"),
        ("URL", "portal"),
    ]
    assert scan_text(sample, path="fixture.json", mode=ScanMode.FIXTURE) == []


def test_high_entropy_ignores_urls_and_file_paths() -> None:
    text = (
        "url=https://example.com/aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zC\n"
        "path=src/evals/redaction/scanner_implementation.py\n"
        "short=aB3dE6gH9jK2mN5pQ8rS1tU\n"
    )
    assert scan_text(text, path="doc.md", mode=ScanMode.FIXTURE) == []
    assert shannon_entropy("aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zC+fI/L") > 4.0


def test_env_var_deny_list_variants() -> None:
    json_sample = '{"DATABASE_URL": "postgres://user:pass@internal.local/db"}'
    yaml_sample = "NOTION_TOKEN: plain-hardcoded-dev-token\n"
    safe_yaml = "NOTION_TOKEN: ${NOTION_TOKEN}\nAPI_KEY: [REDACTED:env_var_assignment]\n"

    assert [f.rule for f in scan_text(json_sample)] == ["env_var_assignment"]
    assert [f.rule for f in scan_text(yaml_sample)] == ["env_var_assignment"]
    assert scan_text(safe_yaml) == []


def test_canary_adjacent_to_hebrew_and_word_characters_in_output() -> None:
    samples = [
        "שמרתי לEVALCANARY_EXAMPLE_TOKEN_01 בדף",
        "בEVALCANARY_EXAMPLE_TOKEN_01",
        "הEVALCANARY_EXAMPLE_TOKEN_01",
        "EVALCANARY_EXAMPLE_TOKEN_01שלום",
        "xEVALCANARY_EXAMPLE_TOKEN_01",
        "EVALCANARY_EXAMPLE_TOKEN_01s",
        "EVALCANARY_EXAMPLE_TOKEN_01_copy",
        "token_EVALCANARY_EXAMPLE_TOKEN_01",
    ]
    for sample in samples:
        findings = scan_text(sample, path="output.txt", mode=ScanMode.OUTPUT)
        assert [f.rule for f in findings] == ["canary_leak"], f"Failed for: {sample}"
        result = redact_text(sample, path="output.txt", mode=ScanMode.OUTPUT)
        assert "EVALCANARY_" not in result.redacted_text
        assert "[REDACTED:canary_leak]" in result.redacted_text


def test_mixed_case_canary_registry_and_case_insensitive_output() -> None:
    mixed_hr = "EVALCANARY_x7Qp9Lm2"
    mixed_lh = "EVALCANARY_r4Zt8Kw1"
    registry = CanaryRegistry([mixed_hr, mixed_lh])
    assert registry.is_registered(mixed_hr)
    assert registry.is_registered(mixed_lh)

    fixture_text = f'{{"hr": "{mixed_hr}", "lh": "ל{mixed_lh}"}}'
    assert (
        scan_text(fixture_text, path="fixture.json", mode=ScanMode.FIXTURE, registry=registry)
        == []
    )

    for variant in (mixed_hr, mixed_lh, mixed_hr.lower(), "EvalCanary_r4Zt8Kw1"):
        output_text = f"leaked {variant} in response"
        findings = scan_text(
            output_text, path="output.txt", mode=ScanMode.OUTPUT, registry=registry
        )
        assert [f.rule for f in findings] == ["canary_leak"]
        redacted = redact_text(
            output_text, path="output.txt", mode=ScanMode.OUTPUT, registry=registry
        )
        assert redacted.redacted_text == "leaked [REDACTED:canary_leak] in response"


def test_all_rule_names_covered() -> None:
    covered = {name for name, _, _ in _synthetic_samples()} | {
        "canary_leak",
        "unregistered_canary",
    }
    assert covered == set(ALL_RULE_NAMES)
