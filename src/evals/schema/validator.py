"""Schema validation for eval suites, cases, criteria, and fixtures (LLD §5.1).

Strictly offline: performs zero model calls and zero Notion writes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from evals.redaction.canaries import CANARY_PATTERN, CanaryRegistry
from evals.redaction.scanner import RedactionFinding, ScanMode, redact_text, scan_file, scan_path

VALID_HUMAN_SIGNOFF = frozenset({"never", "conditional", "always"})
VALID_JUDGE_TYPES = frozenset({"static", "model", "human"})
VALID_SEVERITIES = frozenset({"critical", "major", "minor"})

EXIT_OK = 0
EXIT_SCHEMA_ERROR = 1
EXIT_USAGE_ERROR = 2
EXIT_REDACTION_FINDING = 3


@dataclass(frozen=True)
class ValidationIssue:
    """A schema or structural validation error."""

    kind: str
    path: str
    message: str

    def format_line(self) -> str:
        return f"{self.path} [{self.kind}] {self.message}"

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True)
class ValidationReport:
    """Combined result of schema validation and redaction scanning."""

    target: str
    schema_errors: tuple[ValidationIssue, ...]
    redaction_findings: tuple[RedactionFinding, ...]
    checked_files: tuple[str, ...]

    @property
    def is_valid(self) -> bool:
        return not self.schema_errors and not self.redaction_findings

    @property
    def exit_code(self) -> int:
        if self.redaction_findings:
            return EXIT_REDACTION_FINDING
        if self.schema_errors:
            return EXIT_SCHEMA_ERROR
        return EXIT_OK

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "valid": self.is_valid,
            "exit_code": self.exit_code,
            "checked_files": list(self.checked_files),
            "schema_errors": [issue.to_dict() for issue in self.schema_errors],
            "redaction_findings": [finding.to_dict() for finding in self.redaction_findings],
        }


def _sanitize_issues(
    issues: list[ValidationIssue], registry: CanaryRegistry
) -> tuple[ValidationIssue, ...]:
    """Redact any secret or canary value from validation issue messages."""
    sanitized: list[ValidationIssue] = []
    for issue in issues:
        safe_message = redact_text(
            issue.message, mode=ScanMode.OUTPUT, registry=registry
        ).redacted_text
        sanitized.append(
            ValidationIssue(kind=issue.kind, path=issue.path, message=safe_message)
        )
    return tuple(sanitized)


def _display_path(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return str(path.resolve().relative_to(root.resolve()))
        except ValueError:
            pass
    return str(path)


def _load_structured_file(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(raw)
    return yaml.safe_load(raw)


def _find_first_manifest(directory: Path, stem: str) -> Path | None:
    for ext in (".yaml", ".yml", ".json"):
        candidate = directory / f"{stem}{ext}"
        if candidate.is_file():
            return candidate
    return None


def _collect_data_files(directory: Path, stem: str) -> list[Path]:
    files: list[Path] = []
    single = _find_first_manifest(directory, stem)
    if single is not None:
        files.append(single)
    subdir = directory / stem
    if subdir.is_dir():
        for item in sorted(subdir.rglob("*")):
            if item.is_file() and item.suffix.lower() in {".yaml", ".yml", ".json"}:
                files.append(item)
    return files


def _validate_criterion(
    raw: Any,
    *,
    source: str,
    errors: list[ValidationIssue],
    seen_ids: set[str] | None = None,
) -> str | None:
    if not isinstance(raw, dict):
        errors.append(ValidationIssue("schema", source, "Criterion entry must be a mapping"))
        return None

    crit_id = raw.get("id")
    if not isinstance(crit_id, str) or not crit_id.strip():
        errors.append(ValidationIssue("schema", source, "Criterion missing non-empty string 'id'"))
        crit_id = None
    elif seen_ids is not None:
        if crit_id in seen_ids:
            errors.append(ValidationIssue("schema", source, f"Duplicate criterion id '{crit_id}'"))
        else:
            seen_ids.add(crit_id)

    label = crit_id or "<unknown>"
    description = raw.get("description")
    if not isinstance(description, str) or not description.strip():
        errors.append(
            ValidationIssue(
                "schema", source, f"Criterion '{label}' missing non-empty string 'description'"
            )
        )

    judge_type = raw.get("judge_type")
    if judge_type not in VALID_JUDGE_TYPES:
        allowed = ", ".join(sorted(VALID_JUDGE_TYPES))
        errors.append(
            ValidationIssue(
                "schema",
                source,
                f"Criterion '{label}' has invalid judge_type (expected one of: {allowed})",
            )
        )

    severity = raw.get("severity")
    if severity not in VALID_SEVERITIES:
        allowed = ", ".join(sorted(VALID_SEVERITIES))
        errors.append(
            ValidationIssue(
                "schema",
                source,
                f"Criterion '{label}' has invalid severity (expected one of: {allowed})",
            )
        )

    if "must_pass" in raw and not isinstance(raw["must_pass"], bool):
        errors.append(
            ValidationIssue("schema", source, f"Criterion '{label}' field 'must_pass' must be bool")
        )

    return crit_id


def _resolve_fixture_ref(ref: str, *, slug: str, root: Path) -> Path | None:
    candidates = [
        root / "fixtures" / slug / ref,
        root / "fixtures" / ref,
        root / ref,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _validate_structured_syntax(
    path: Path, *, root: Path | None, errors: list[ValidationIssue]
) -> None:
    suffix = path.suffix.lower()
    if suffix not in {".json", ".yaml", ".yml"}:
        return
    display = _display_path(path, root)
    try:
        _load_structured_file(path)
    except (json.JSONDecodeError, yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
        errors.append(
            ValidationIssue("fixture", display, f"Failed to parse {suffix} file: {exc}")
        )


def validate_suite(
    slug: str,
    *,
    root: Path,
    canary_registry: CanaryRegistry | None = None,
) -> ValidationReport:
    """Validate a suite's manifest, criteria, cases, fixtures, and redaction compliance."""
    root = root.resolve()
    suite_dir = root / "suites" / slug
    errors: list[ValidationIssue] = []
    findings: list[RedactionFinding] = []
    checked: list[str] = []
    registry = canary_registry if canary_registry is not None else CanaryRegistry()

    if not suite_dir.is_dir():
        errors.append(
            ValidationIssue(
                "schema",
                _display_path(suite_dir, root),
                f"Suite directory not found for slug '{slug}'",
            )
        )
        return ValidationReport(
            target=f"suite:{slug}",
            schema_errors=tuple(errors),
            redaction_findings=(),
            checked_files=(),
        )

    # 1. Suite manifest.
    suite_file = _find_first_manifest(suite_dir, "suite")
    if suite_file is None:
        errors.append(
            ValidationIssue(
                "schema",
                _display_path(suite_dir, root),
                "Missing suite manifest (suite.yaml, suite.yml, or suite.json)",
            )
        )
    else:
        display = _display_path(suite_file, root)
        checked.append(display)
        try:
            suite_data = _load_structured_file(suite_file)
        except (json.JSONDecodeError, yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
            errors.append(ValidationIssue("schema", display, f"Invalid suite manifest: {exc}"))
            suite_data = None

        if isinstance(suite_data, dict):
            manifest_slug = suite_data.get("slug")
            if manifest_slug != slug:
                errors.append(
                    ValidationIssue(
                        "schema",
                        display,
                        f"Suite manifest slug '{manifest_slug}' must match directory '{slug}'",
                    )
                )
            for field in ("name", "target", "version"):
                val = suite_data.get(field)
                if not isinstance(val, str) or not val.strip():
                    errors.append(
                        ValidationIssue(
                            "schema", display, f"Suite manifest missing non-empty string '{field}'"
                        )
                    )
            if (
                "human_signoff" in suite_data
                and suite_data["human_signoff"] not in VALID_HUMAN_SIGNOFF
            ):
                allowed = ", ".join(sorted(VALID_HUMAN_SIGNOFF))
                errors.append(
                    ValidationIssue(
                        "schema",
                        display,
                        f"Invalid human_signoff (expected one of: {allowed})",
                    )
                )
            for threshold_field in ("pass_threshold", "case_threshold"):
                if threshold_field in suite_data:
                    val = suite_data[threshold_field]
                    if (
                        isinstance(val, bool)
                        or not isinstance(val, (int, float))
                        or not (0.0 <= float(val) <= 1.0)
                    ):
                        errors.append(
                            ValidationIssue(
                                "schema",
                                display,
                                f"Field '{threshold_field}' must be a number between 0.0 and 1.0",
                            )
                        )
            if "canary_registry" in suite_data:
                canaries = suite_data["canary_registry"]
                if not isinstance(canaries, list) or not all(isinstance(c, str) for c in canaries):
                    errors.append(
                        ValidationIssue(
                            "schema",
                            display,
                            "Field 'canary_registry' must be a list of EVALCANARY_* strings",
                        )
                    )
                else:
                    valid_extra: list[str] = []
                    for token in canaries:
                        if not CANARY_PATTERN.fullmatch(token):
                            errors.append(
                                ValidationIssue(
                                    "schema",
                                    display,
                                    "Invalid canary entry in 'canary_registry' "
                                    "(must match EVALCANARY_[A-Za-z0-9_]{4,})",
                                )
                            )
                        else:
                            valid_extra.append(token)
                    if valid_extra:
                        registry = registry.merged_with(valid_extra)
        elif suite_data is not None:
            errors.append(ValidationIssue("schema", display, "Suite manifest must be a mapping"))

    # 2. Criteria files.
    known_criteria_ids: set[str] = set()
    criteria_files = _collect_data_files(suite_dir, "criteria")
    for cfile in criteria_files:
        display = _display_path(cfile, root)
        checked.append(display)
        try:
            raw = _load_structured_file(cfile)
        except (json.JSONDecodeError, yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
            errors.append(ValidationIssue("schema", display, f"Invalid criteria file: {exc}"))
            continue
        if isinstance(raw, dict) and "criteria" in raw and isinstance(raw["criteria"], list):
            items = raw["criteria"]
        elif isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = [raw]
        else:
            errors.append(
                ValidationIssue(
                    "schema", display, "Criteria file must contain a mapping or list of criteria"
                )
            )
            continue
        for item in items:
            _validate_criterion(item, source=display, errors=errors, seen_ids=known_criteria_ids)

    # 3. Cases files.
    case_files = _collect_data_files(suite_dir, "cases")
    seen_case_ids: set[str] = set()
    referenced_fixtures: list[Path] = []
    total_cases = 0

    if not case_files:
        errors.append(
            ValidationIssue(
                "schema",
                _display_path(suite_dir, root),
                "Suite must define at least one case file (cases.yaml or cases/*.yaml)",
            )
        )

    for case_file in case_files:
        display = _display_path(case_file, root)
        checked.append(display)
        try:
            raw = _load_structured_file(case_file)
        except (json.JSONDecodeError, yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
            errors.append(ValidationIssue("schema", display, f"Invalid cases file: {exc}"))
            continue

        if isinstance(raw, dict) and "cases" in raw and isinstance(raw["cases"], list):
            items = raw["cases"]
        elif isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = [raw]
        else:
            errors.append(
                ValidationIssue("schema", display, "Cases file must contain a mapping or list")
            )
            continue

        for case in items:
            total_cases += 1
            if not isinstance(case, dict):
                errors.append(ValidationIssue("schema", display, "Case entry must be a mapping"))
                continue

            case_id = case.get("id")
            if not isinstance(case_id, str) or not case_id.strip():
                errors.append(
                    ValidationIssue("schema", display, "Case missing non-empty string 'id'")
                )
                case_label = "<unknown>"
            else:
                case_label = case_id
                if case_id in seen_case_ids:
                    errors.append(
                        ValidationIssue("schema", display, f"Duplicate case id '{case_id}'")
                    )
                else:
                    seen_case_ids.add(case_id)

            if "suite" in case and case["suite"] != slug:
                errors.append(
                    ValidationIssue(
                        "schema",
                        display,
                        f"Case '{case_label}' suite '{case['suite']}' does not match '{slug}'",
                    )
                )

            title = case.get("title")
            if not isinstance(title, str) or not title.strip():
                errors.append(
                    ValidationIssue(
                        "schema", display, f"Case '{case_label}' missing non-empty string 'title'"
                    )
                )

            case_input = case.get("input")
            if case_input is None or (isinstance(case_input, str) and not case_input.strip()):
                errors.append(
                    ValidationIssue(
                        "schema", display, f"Case '{case_label}' missing non-empty 'input'"
                    )
                )

            expected = case.get("expected_behavior")
            if not isinstance(expected, str) or not expected.strip():
                errors.append(
                    ValidationIssue(
                        "schema",
                        display,
                        f"Case '{case_label}' missing non-empty string 'expected_behavior'",
                    )
                )

            if "must_pass" in case and not isinstance(case["must_pass"], bool):
                errors.append(
                    ValidationIssue(
                        "schema", display, f"Case '{case_label}' field 'must_pass' must be bool"
                    )
                )

            if "repeat" in case:
                rep = case["repeat"]
                if isinstance(rep, bool) or not isinstance(rep, int) or rep < 1:
                    errors.append(
                        ValidationIssue(
                            "schema",
                            display,
                            f"Case '{case_label}' field 'repeat' must be int >= 1",
                        )
                    )

            case_criteria = case.get("criteria")
            if not isinstance(case_criteria, list) or not case_criteria:
                errors.append(
                    ValidationIssue(
                        "schema",
                        display,
                        f"Case '{case_label}' must specify a non-empty 'criteria' list",
                    )
                )
            else:
                for entry in case_criteria:
                    if isinstance(entry, str):
                        if entry not in known_criteria_ids:
                            errors.append(
                                ValidationIssue(
                                    "schema",
                                    display,
                                    f"Case '{case_label}' references unknown criterion '{entry}'",
                                )
                            )
                    elif isinstance(entry, dict):
                        _validate_criterion(entry, source=display, errors=errors)
                    else:
                        errors.append(
                            ValidationIssue(
                                "schema",
                                display,
                                f"Case '{case_label}' criterion must be an id string or mapping",
                            )
                        )

            fixture_field = case.get("fixture")
            if fixture_field is not None:
                refs = [fixture_field] if isinstance(fixture_field, str) else fixture_field
                if not isinstance(refs, list) or not all(
                    isinstance(r, str) and r.strip() for r in refs
                ):
                    errors.append(
                        ValidationIssue(
                            "schema",
                            display,
                            f"Case '{case_label}' field 'fixture' must be a path string or list",
                        )
                    )
                else:
                    for ref in refs:
                        resolved = _resolve_fixture_ref(ref, slug=slug, root=root)
                        if resolved is None:
                            errors.append(
                                ValidationIssue(
                                    "fixture",
                                    display,
                                    f"Case '{case_label}' references missing fixture '{ref}'",
                                )
                            )
                        else:
                            referenced_fixtures.append(resolved)

    if case_files and total_cases == 0:
        errors.append(
            ValidationIssue("schema", _display_path(suite_dir, root), "Suite has zero cases")
        )

    # 4. Scan suite files and fixtures (FIXTURE mode).
    findings.extend(scan_path(suite_dir, mode=ScanMode.FIXTURE, registry=registry, root=root))

    scanned_fixture_paths: set[Path] = set()
    suite_fixtures_dir = root / "fixtures" / slug
    fixture_targets: list[Path] = []
    if suite_fixtures_dir.is_dir():
        fixture_targets.append(suite_fixtures_dir)
    fixture_targets.extend(referenced_fixtures)

    for target in fixture_targets:
        if target.is_file():
            resolved = target.resolve()
            if resolved in scanned_fixture_paths:
                continue
            scanned_fixture_paths.add(resolved)
            checked.append(_display_path(resolved, root))
            _validate_structured_syntax(resolved, root=root, errors=errors)
            findings.extend(
                scan_file(
                    resolved,
                    mode=ScanMode.FIXTURE,
                    registry=registry,
                    display_path=_display_path(resolved, root),
                )
            )
        elif target.is_dir():
            for item in sorted(target.rglob("*")):
                if not item.is_file():
                    continue
                resolved = item.resolve()
                if resolved in scanned_fixture_paths:
                    continue
                scanned_fixture_paths.add(resolved)
                checked.append(_display_path(resolved, root))
                _validate_structured_syntax(resolved, root=root, errors=errors)
                findings.extend(
                    scan_file(
                        resolved,
                        mode=ScanMode.FIXTURE,
                        registry=registry,
                        display_path=_display_path(resolved, root),
                    )
                )

    return ValidationReport(
        target=f"suite:{slug}",
        schema_errors=_sanitize_issues(errors, registry),
        redaction_findings=tuple(findings),
        checked_files=tuple(dict.fromkeys(checked)),
    )


def validate_fixture(
    target: Path,
    *,
    canary_registry: CanaryRegistry | None = None,
    root: Path | None = None,
) -> ValidationReport:
    """Validate a fixture file or directory (syntax + redaction scan in FIXTURE mode)."""
    errors: list[ValidationIssue] = []
    checked: list[str] = []
    registry = canary_registry if canary_registry is not None else CanaryRegistry()

    if not target.exists():
        errors.append(
            ValidationIssue("fixture", str(target), f"Fixture path not found: {target}")
        )
        return ValidationReport(
            target=f"fixture:{target}",
            schema_errors=tuple(errors),
            redaction_findings=(),
            checked_files=(),
        )

    files = [target] if target.is_file() else [p for p in sorted(target.rglob("*")) if p.is_file()]
    for item in files:
        checked.append(_display_path(item, root))
        _validate_structured_syntax(item, root=root, errors=errors)

    findings = scan_path(target, mode=ScanMode.FIXTURE, registry=registry, root=root)
    return ValidationReport(
        target=f"fixture:{_display_path(target, root)}",
        schema_errors=_sanitize_issues(errors, registry),
        redaction_findings=tuple(findings),
        checked_files=tuple(checked),
    )


def validate_output(
    target: Path,
    *,
    canary_registry: CanaryRegistry | None = None,
    root: Path | None = None,
) -> ValidationReport:
    """Validate subject output (redaction scan in OUTPUT mode; any canary fails)."""
    errors: list[ValidationIssue] = []
    checked: list[str] = []
    registry = canary_registry if canary_registry is not None else CanaryRegistry()

    if not target.exists():
        errors.append(ValidationIssue("fixture", str(target), f"Output path not found: {target}"))
        return ValidationReport(
            target=f"output:{target}",
            schema_errors=tuple(errors),
            redaction_findings=(),
            checked_files=(),
        )

    files = [target] if target.is_file() else [p for p in sorted(target.rglob("*")) if p.is_file()]
    for item in files:
        checked.append(_display_path(item, root))

    findings = scan_path(target, mode=ScanMode.OUTPUT, registry=registry, root=root)
    return ValidationReport(
        target=f"output:{_display_path(target, root)}",
        schema_errors=tuple(errors),
        redaction_findings=tuple(findings),
        checked_files=tuple(checked),
    )
