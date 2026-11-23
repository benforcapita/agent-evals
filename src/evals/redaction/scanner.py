"""Redaction scanner and text redactor per LLD §8.

Findings report only the rule name, file path, line, and column — never the
matched secret value. Before any external write, `redact_text` replaces every
matched span with `[REDACTED:{rule}]`.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from evals.redaction.canaries import CanaryRegistry, find_canaries
from evals.redaction.placeholders import find_placeholder_spans, is_valid_placeholder
from evals.redaction.rules import (
    ENV_REF_VALUE_PATTERN,
    ENV_VAR_ASSIGNMENT_PATTERN,
    HIGH_ENTROPY_MIN_LENGTH,
    HIGH_ENTROPY_THRESHOLD,
    HIGH_ENTROPY_TOKEN_PATTERN,
    KNOWN_KEY_RULES,
    REDACTED_MARKER_PATTERN,
    SAFE_LITERAL_VALUES,
    URL_PATTERN,
    looks_like_file_path,
    shannon_entropy,
)

SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "node_modules",
    }
)


class ScanMode(StrEnum):
    """Scanning context: fixtures allow registered canaries; output forbids them."""

    FIXTURE = "fixture"
    OUTPUT = "output"


@dataclass(frozen=True)
class RedactionFinding:
    """A single scanner finding. Intentionally omits the matched secret value."""

    rule: str
    path: str
    line: int
    column: int
    message: str

    def format_line(self) -> str:
        return f"{self.path}:{self.line}:{self.column} [{self.rule}] {self.message}"

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
        }


@dataclass(frozen=True)
class RedactionResult:
    """Result of scanning and redacting a text buffer."""

    redacted_text: str
    findings: tuple[RedactionFinding, ...]

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


@dataclass(frozen=True)
class _InternalMatch:
    rule: str
    start: int
    end: int
    message: str


def _overlaps(span: tuple[int, int], existing: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < ex_end and ex_start < end for ex_start, ex_end in existing)


def _line_starts(text: str) -> list[int]:
    starts = [0]
    idx = text.find("\n")
    while idx != -1:
        starts.append(idx + 1)
        idx = text.find("\n", idx + 1)
    return starts


def _offset_to_line_col(offset: int, starts: list[int]) -> tuple[int, int]:
    line_idx = bisect_right(starts, offset) - 1
    line = line_idx + 1
    col = offset - starts[line_idx] + 1
    return line, col


def _collect_matches(
    text: str,
    *,
    mode: ScanMode,
    registry: CanaryRegistry,
) -> list[_InternalMatch]:
    ignored_spans: list[tuple[int, int]] = []
    ignored_spans.extend(find_placeholder_spans(text))
    for marker in REDACTED_MARKER_PATTERN.finditer(text):
        ignored_spans.append((marker.start(), marker.end()))

    matches: list[_InternalMatch] = []
    matched_spans: list[tuple[int, int]] = []

    def add_match(rule: str, start: int, end: int, message: str) -> None:
        span = (start, end)
        if _overlaps(span, ignored_spans) or _overlaps(span, matched_spans):
            return
        matches.append(_InternalMatch(rule=rule, start=start, end=end, message=message))
        matched_spans.append(span)

    # 1. Canary tokens (EVALCANARY_*).
    for token, start, end in find_canaries(text, case_insensitive=(mode is ScanMode.OUTPUT)):
        span = (start, end)
        if _overlaps(span, ignored_spans):
            continue
        if mode is ScanMode.OUTPUT:
            add_match(
                "canary_leak",
                start,
                end,
                "Canary token leaked in subject output",
            )
        elif registry.is_registered(token):
            ignored_spans.append(span)
        else:
            add_match(
                "unregistered_canary",
                start,
                end,
                "Unregistered EVALCANARY_ token in fixture",
            )

    # 2. Known key format rules.
    for rule in KNOWN_KEY_RULES:
        for match in rule.pattern.finditer(text):
            add_match(rule.name, match.start(), match.end(), rule.description)

    # 3. Deny list of environment variable assignments.
    for match in ENV_VAR_ASSIGNMENT_PATTERN.finditer(text):
        env_name = match.group("json_name") or match.group("kv_name")
        val_group = "json_val" if match.group("json_val") is not None else "kv_val"
        raw_val = match.group(val_group)
        val_start, val_end = match.span(val_group)

        if len(raw_val) >= 2 and raw_val[0] == raw_val[-1] and raw_val[0] in {'"', "'"}:
            inner_val = raw_val[1:-1]
            inner_start = val_start + 1
            inner_end = val_end - 1
        else:
            inner_val = raw_val
            inner_start = val_start
            inner_end = val_end

        stripped = inner_val.strip()
        if not stripped or stripped.lower() in SAFE_LITERAL_VALUES:
            continue
        if is_valid_placeholder(stripped):
            continue
        if REDACTED_MARKER_PATTERN.fullmatch(stripped):
            continue
        if ENV_REF_VALUE_PATTERN.fullmatch(stripped):
            continue
        if mode is ScanMode.FIXTURE and registry.is_registered(stripped):
            continue
        if _overlaps((inner_start, inner_end), matched_spans):
            continue
        add_match(
            "env_var_assignment",
            inner_start,
            inner_end,
            f"Hardcoded value assigned to denied env var {env_name}",
        )

    # 4. High-entropy tokens (Shannon entropy > 4.0 on 24+ char tokens).
    url_spans = [(m.start(), m.end()) for m in URL_PATTERN.finditer(text)]
    for match in HIGH_ENTROPY_TOKEN_PATTERN.finditer(text):
        token = match.group(1)
        span = (match.start(1), match.end(1))
        if len(token) < HIGH_ENTROPY_MIN_LENGTH:
            continue
        if (
            _overlaps(span, ignored_spans)
            or _overlaps(span, matched_spans)
            or _overlaps(span, url_spans)
        ):
            continue
        if looks_like_file_path(token):
            continue
        if shannon_entropy(token) > HIGH_ENTROPY_THRESHOLD:
            add_match(
                "high_entropy_token",
                span[0],
                span[1],
                "High-entropy token detected (entropy > 4.0, length >= 24)",
            )

    matches.sort(key=lambda item: (item.start, item.end))
    return matches


def scan_text(
    text: str,
    *,
    path: str = "<memory>",
    mode: ScanMode = ScanMode.FIXTURE,
    registry: CanaryRegistry | None = None,
) -> list[RedactionFinding]:
    """Scan text and return findings without ever exposing matched values."""
    effective_registry = registry if registry is not None else CanaryRegistry()
    matches = _collect_matches(text, mode=mode, registry=effective_registry)
    if not matches:
        return []
    starts = _line_starts(text)
    findings: list[RedactionFinding] = []
    for item in matches:
        line, col = _offset_to_line_col(item.start, starts)
        findings.append(
            RedactionFinding(
                rule=item.rule,
                path=path,
                line=line,
                column=col,
                message=item.message,
            )
        )
    return findings


def redact_text(
    text: str,
    *,
    path: str = "<memory>",
    mode: ScanMode = ScanMode.OUTPUT,
    registry: CanaryRegistry | None = None,
) -> RedactionResult:
    """Scan text and replace every matched span with `[REDACTED:{rule}]`."""
    effective_registry = registry if registry is not None else CanaryRegistry()
    matches = _collect_matches(text, mode=mode, registry=effective_registry)
    if not matches:
        return RedactionResult(redacted_text=text, findings=())

    starts = _line_starts(text)
    findings: list[RedactionFinding] = []
    chunks: list[str] = []
    cursor = 0
    for item in matches:
        chunks.append(text[cursor : item.start])
        chunks.append(f"[REDACTED:{item.rule}]")
        cursor = item.end
        line, col = _offset_to_line_col(item.start, starts)
        findings.append(
            RedactionFinding(
                rule=item.rule,
                path=path,
                line=line,
                column=col,
                message=item.message,
            )
        )
    chunks.append(text[cursor:])
    return RedactionResult(redacted_text="".join(chunks), findings=tuple(findings))


def _is_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            sample = fh.read(8192)
    except OSError:
        return True
    return b"\x00" in sample


def scan_file(
    path: Path,
    *,
    mode: ScanMode = ScanMode.FIXTURE,
    registry: CanaryRegistry | None = None,
    display_path: str | None = None,
) -> list[RedactionFinding]:
    """Scan a single UTF-8 text file; binary files are skipped."""
    if not path.is_file() or _is_binary_file(path):
        return []
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    return scan_text(
        content,
        path=display_path if display_path is not None else str(path),
        mode=mode,
        registry=registry,
    )


def scan_path(
    target: Path,
    *,
    mode: ScanMode = ScanMode.FIXTURE,
    registry: CanaryRegistry | None = None,
    root: Path | None = None,
) -> list[RedactionFinding]:
    """Scan a file or recursively scan a directory."""
    if target.is_file():
        display = (
            str(target.relative_to(root))
            if root and target.is_relative_to(root)
            else str(target)
        )
        return scan_file(target, mode=mode, registry=registry, display_path=display)

    findings: list[RedactionFinding] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        display = str(path.relative_to(root)) if root and path.is_relative_to(root) else str(path)
        findings.extend(scan_file(path, mode=mode, registry=registry, display_path=display))
    return findings
