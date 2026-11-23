"""Redaction scanner, placeholder conventions, and canary registry (LLD §8)."""

from evals.redaction.canaries import (
    CANARY_PATTERN,
    CANARY_PREFIX,
    DEFAULT_CANARIES,
    CanaryRegistry,
    find_canaries,
)
from evals.redaction.placeholders import (
    VALID_PLACEHOLDER_KINDS,
    Placeholder,
    extract_placeholders,
    find_placeholder_spans,
    is_valid_placeholder,
)
from evals.redaction.rules import (
    ALL_RULE_NAMES,
    DENY_LIST_ENV_VARS,
    HIGH_ENTROPY_MIN_LENGTH,
    HIGH_ENTROPY_THRESHOLD,
    KNOWN_KEY_RULES,
    PatternRule,
    shannon_entropy,
)
from evals.redaction.scanner import (
    RedactionFinding,
    RedactionResult,
    ScanMode,
    redact_text,
    scan_file,
    scan_path,
    scan_text,
)

__all__ = [
    "ALL_RULE_NAMES",
    "CANARY_PATTERN",
    "CANARY_PREFIX",
    "DEFAULT_CANARIES",
    "DENY_LIST_ENV_VARS",
    "HIGH_ENTROPY_MIN_LENGTH",
    "HIGH_ENTROPY_THRESHOLD",
    "KNOWN_KEY_RULES",
    "VALID_PLACEHOLDER_KINDS",
    "CanaryRegistry",
    "PatternRule",
    "Placeholder",
    "RedactionFinding",
    "RedactionResult",
    "ScanMode",
    "extract_placeholders",
    "find_canaries",
    "find_placeholder_spans",
    "is_valid_placeholder",
    "redact_text",
    "scan_file",
    "scan_path",
    "scan_text",
    "shannon_entropy",
]
