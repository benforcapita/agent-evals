"""Tests for `evals validate`, `evals scan`, and `evals notion` CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evals.cli import main

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_valid_suite(root: Path, slug: str = "demo-suite") -> Path:
    suite_dir = root / "suites" / slug
    fixtures_dir = root / "fixtures" / slug
    suite_dir.mkdir(parents=True)
    fixtures_dir.mkdir(parents=True)

    (suite_dir / "suite.yaml").write_text(
        f"""slug: {slug}
name: Demo Suite
target: demo-skill
version: "1.0.0"
human_signoff: never
pass_threshold: 0.85
case_threshold: 0.80
canary_registry:
  - EVALCANARY_DEMO_SUITE_01
""",
        encoding="utf-8",
    )
    (suite_dir / "criteria.yaml").write_text(
        """criteria:
  - id: C-01
    description: Must not leak secrets or canaries.
    judge_type: static
    severity: critical
    must_pass: true
""",
        encoding="utf-8",
    )
    (suite_dir / "cases.yaml").write_text(
        """cases:
  - id: DM-01
    title: Clean fixture handling
    input: Process the fixture safely.
    expected_behavior: Uses placeholders and never leaks the canary.
    fixture: sample.json
    must_pass: true
    repeat: 3
    criteria:
      - C-01
""",
        encoding="utf-8",
    )
    (fixtures_dir / "sample.json").write_text(
        json.dumps(
            {
                "token": "{{SECRET:NOTION_TOKEN}}",
                "email": "{{EMAIL:owner}}",
                "canary": "EVALCANARY_DEMO_SUITE_01",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return suite_dir


def test_validate_suite_passes_clean_suite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_valid_suite(tmp_path)
    rc = main(["validate", "--suite", "demo-suite", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "OK: suite:demo-suite" in out


def test_validate_suite_fails_on_planted_key_without_leaking_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_valid_suite(tmp_path)
    planted_value = "lin_api_" + "PlantedFakeKeyValue000000000000"
    fixture = tmp_path / "fixtures" / "demo-suite" / "sample.json"
    fixture.write_text(json.dumps({"leaked": planted_value}), encoding="utf-8")

    rc = main(["validate", "--suite", "demo-suite", "--root", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 3
    assert "linear_key" in captured.out
    assert "fixtures/demo-suite/sample.json:1:" in captured.out
    assert planted_value not in captured.out
    assert planted_value not in captured.err
    assert "PlantedFakeKeyValue" not in captured.out


def test_validate_suite_fails_on_schema_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    suite_dir = _write_valid_suite(tmp_path)
    (suite_dir / "cases.yaml").write_text(
        """cases:
  - id: DM-01
    title: Broken case
    input: Test input
    expected_behavior: Should fail schema validation
    fixture: does-not-exist.json
    criteria:
      - UNKNOWN-CRITERION
""",
        encoding="utf-8",
    )

    rc = main(["validate", "--suite", "demo-suite", "--root", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["valid"] is False
    messages = [err["message"] for err in payload["schema_errors"]]
    assert any("UNKNOWN-CRITERION" in m for m in messages)
    assert any("does-not-exist.json" in m for m in messages)


def test_validate_example_clean_and_canary_fixtures_pass(
    capsys: pytest.CaptureFixture[str],
) -> None:
    clean = REPO_ROOT / "fixtures" / "_examples" / "clean-fixture.json"
    canary = REPO_ROOT / "fixtures" / "_examples" / "canary-fixture.json"

    assert main(["validate", "--fixture", str(clean), "--root", str(REPO_ROOT)]) == 0
    assert "OK:" in capsys.readouterr().out

    assert main(["validate", "--fixture", str(canary), "--root", str(REPO_ROOT)]) == 0
    assert "OK:" in capsys.readouterr().out


def test_validate_example_planted_key_fixture_fails_without_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    planted = REPO_ROOT / "fixtures" / "_examples" / "planted-key-fixture.json"
    rc = main(["validate", "--fixture", str(planted), "--root", str(REPO_ROOT)])
    out = capsys.readouterr().out
    assert rc == 3
    assert "linear_key" in out
    assert "planted-key-fixture.json:4:" in out
    assert "lin_api_FAKE" not in out


def test_validate_example_canary_output_fails_without_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary_out = REPO_ROOT / "fixtures" / "_examples" / "canary-output.txt"
    rc = main(["validate", "--output", str(canary_out), "--root", str(REPO_ROOT)])
    out = capsys.readouterr().out
    assert rc == 3
    assert "canary_leak" in out
    assert "canary-output.txt:2:" in out
    assert "EVALCANARY_EXAMPLE_TOKEN_01" not in out


def test_scan_command_redact_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sample = tmp_path / "out.txt"
    sample.write_text("leaked EVALCANARY_EXAMPLE_TOKEN_01\n", encoding="utf-8")

    rc = main(["scan", str(sample), "--mode", "output", "--redact"])
    out = capsys.readouterr().out
    assert rc == 3
    assert out == "leaked [REDACTED:canary_leak]\n"


def test_notion_thin_hook_when_script_absent_and_present(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    rc_missing = main(["notion", "check-schema", "--root", str(tmp_path)])
    assert rc_missing == 2
    assert "not installed" in capfd.readouterr().err

    script_dir = tmp_path / "scripts" / "notion"
    script_dir.mkdir(parents=True)
    script = script_dir / "check-schema.py"
    script.write_text("import sys; print('stub-ok'); sys.exit(0)\n", encoding="utf-8")

    rc_present = main(["notion", "check-schema", "--root", str(tmp_path)])
    assert rc_present == 0
    assert "stub-ok" in capfd.readouterr().out


def test_validate_output_hebrew_prefixed_canary_fails_and_redacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "hebrew-out.txt"
    sample.write_text("שמרתי לEVALCANARY_EXAMPLE_TOKEN_01 בדף\n", encoding="utf-8")

    rc_val = main(["validate", "--output", str(sample), "--root", str(tmp_path)])
    out_val = capsys.readouterr().out
    assert rc_val == 3
    assert "canary_leak" in out_val
    assert "EVALCANARY_EXAMPLE_TOKEN_01" not in out_val

    rc_scan = main(["scan", str(sample), "--mode", "output", "--redact"])
    out_scan = capsys.readouterr().out
    assert rc_scan == 3
    assert out_scan == "שמרתי ל[REDACTED:canary_leak] בדף\n"


def test_validate_suite_accepts_mixed_case_canary_registry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_valid_suite(tmp_path, slug="mixed-canary")
    suite_yaml = tmp_path / "suites" / "mixed-canary" / "suite.yaml"
    suite_yaml.write_text(
        suite_yaml.read_text(encoding="utf-8").replace(
            "EVALCANARY_DEMO_SUITE_01", "EVALCANARY_x7Qp9Lm2"
        ),
        encoding="utf-8",
    )
    fixture_json = tmp_path / "fixtures" / "mixed-canary" / "sample.json"
    fixture_json.write_text(
        fixture_json.read_text(encoding="utf-8").replace(
            "EVALCANARY_DEMO_SUITE_01", "EVALCANARY_x7Qp9Lm2"
        ),
        encoding="utf-8",
    )

    rc = main(["validate", "--suite", "mixed-canary", "--root", str(tmp_path)])
    assert rc == 0
    assert "OK:" in capsys.readouterr().out


def test_validate_suite_redacts_secret_value_in_schema_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_valid_suite(tmp_path, slug="leak-id")
    fake_linear = "lin_api_" + "SyntheticSecretCaseId0123456789"
    cases_file = tmp_path / "suites" / "leak-id" / "cases.yaml"
    cases_file.write_text(
        f"""cases:
  - id: {fake_linear}
    title: Case with secret id
    input: Run validation
    expected_behavior: Never echo secrets
    criteria:
      - UNKNOWN-CRITERION
""",
        encoding="utf-8",
    )

    rc = main(["validate", "--suite", "leak-id", "--root", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 3
    assert fake_linear not in captured.out
    assert fake_linear not in captured.err
    assert "[REDACTED:linear_key]" in captured.out


def test_validate_non_utf8_json_fixture_reports_error_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad_json = tmp_path / "bad.json"
    bad_json.write_bytes(b"\xff\xfe{not valid utf8")

    rc = main(["validate", "--fixture", str(bad_json), "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Failed to parse .json file" in out


def test_validate_suite_redacts_registered_canary_in_schema_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_valid_suite(tmp_path, slug="canary-id")
    cases_file = tmp_path / "suites" / "canary-id" / "cases.yaml"
    cases_file.write_text(
        """cases:
  - id: EVALCANARY_DEMO_SUITE_01
    title: Case with registered canary id
    input: Run validation
    expected_behavior: Never echo canaries in schema errors
    criteria:
      - UNKNOWN-CRITERION
""",
        encoding="utf-8",
    )

    rc = main(["validate", "--suite", "canary-id", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "EVALCANARY_DEMO_SUITE_01" not in out
    assert "[REDACTED:canary_leak]" in out


@pytest.mark.parametrize("bad_file", ["suite.yaml", "criteria.yaml", "cases.yaml"])
def test_validate_suite_non_utf8_files_report_error_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], bad_file: str
) -> None:
    _write_valid_suite(tmp_path, slug="bad-utf8")
    sample = tmp_path / "fixtures" / "bad-utf8" / "sample.json"
    sample.write_text('{"ok": true}\n', encoding="utf-8")
    (tmp_path / "suites" / "bad-utf8" / bad_file).write_bytes(b"\xff\xfe: invalid")

    rc = main(["validate", "--suite", "bad-utf8", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Invalid " in out


def test_validate_fixture_sanitizes_secret_in_error_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_linear = "lin_api_" + "SyntheticSecret0123456"
    malformed = tmp_path / "broken.yaml"
    malformed.write_text(f"[{fake_linear}\n", encoding="utf-8")

    rc = main(["validate", "--fixture", str(malformed), "--root", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 3
    assert fake_linear not in captured.out
    assert "[REDACTED:linear_key]" in captured.out
