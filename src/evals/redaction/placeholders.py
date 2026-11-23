"""Placeholder conventions for sanitized eval fixtures (LLD §8)."""

from __future__ import annotations

import re
from dataclasses import dataclass

PLACEHOLDER_PATTERN = re.compile(
    r"\{\{(?P<kind>SECRET|EMAIL|PHONE|URL):(?P<label>[A-Za-z0-9._-]+)\}\}"
)
SECRET_LABEL_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
GENERIC_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ANY_MUSTACHE_PATTERN = re.compile(r"\{\{([^{}]+)\}\}")

VALID_PLACEHOLDER_KINDS = frozenset({"SECRET", "EMAIL", "PHONE", "URL"})


@dataclass(frozen=True)
class Placeholder:
    kind: str
    label: str
    start: int
    end: int

    @property
    def raw(self) -> str:
        return f"{{{{{self.kind}:{self.label}}}}}"


def is_valid_placeholder(value: str) -> bool:
    """Return True if value is a single well-formed fixture placeholder."""
    stripped = value.strip()
    match = PLACEHOLDER_PATTERN.fullmatch(stripped)
    if not match:
        return False
    kind = match.group("kind")
    label = match.group("label")
    if kind == "SECRET":
        return bool(SECRET_LABEL_PATTERN.fullmatch(label))
    return bool(GENERIC_LABEL_PATTERN.fullmatch(label))


def find_placeholder_spans(text: str) -> list[tuple[int, int]]:
    """Return character spans of all valid placeholders in text."""
    spans: list[tuple[int, int]] = []
    for match in PLACEHOLDER_PATTERN.finditer(text):
        kind = match.group("kind")
        label = match.group("label")
        if kind == "SECRET" and not SECRET_LABEL_PATTERN.fullmatch(label):
            continue
        if kind != "SECRET" and not GENERIC_LABEL_PATTERN.fullmatch(label):
            continue
        spans.append((match.start(), match.end()))
    return spans


def extract_placeholders(text: str) -> list[Placeholder]:
    """Return all valid placeholders found in text."""
    results: list[Placeholder] = []
    for match in PLACEHOLDER_PATTERN.finditer(text):
        kind = match.group("kind")
        label = match.group("label")
        if kind == "SECRET" and not SECRET_LABEL_PATTERN.fullmatch(label):
            continue
        if kind != "SECRET" and not GENERIC_LABEL_PATTERN.fullmatch(label):
            continue
        results.append(
            Placeholder(kind=kind, label=label, start=match.start(), end=match.end())
        )
    return results
