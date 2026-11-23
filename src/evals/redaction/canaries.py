"""Canary registry for EVALCANARY_ tokens (LLD §8).

Registered EVALCANARY_* tokens are allowed in fixtures so suites can test
whether a subject leaks sensitive fixture content into its output. Any
EVALCANARY_* token appearing in subject output fails validation and is
redacted as [REDACTED:canary_leak].
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

import yaml

CANARY_PREFIX = "EVALCANARY_"
CANARY_PATTERN = re.compile(r"\bEVALCANARY_[A-Z0-9_]{4,}\b")

DEFAULT_CANARIES: frozenset[str] = frozenset(
    {
        "EVALCANARY_EXAMPLE_TOKEN_01",
        "EVALCANARY_EXAMPLE_SECRET_02",
        "EVALCANARY_FIXTURE_MARKER_01",
    }
)


class CanaryRegistry:
    """Registry of approved synthetic EVALCANARY_* tokens."""

    def __init__(self, tokens: Iterable[str] | None = None) -> None:
        self._tokens: set[str] = set()
        source = DEFAULT_CANARIES if tokens is None else tokens
        for token in source:
            self.register(token)

    def register(self, token: str) -> None:
        if not CANARY_PATTERN.fullmatch(token):
            raise ValueError(
                f"Invalid canary token format: must match {CANARY_PATTERN.pattern}"
            )
        self._tokens.add(token)

    def is_registered(self, token: str) -> bool:
        return token in self._tokens

    @property
    def tokens(self) -> frozenset[str]:
        return frozenset(self._tokens)

    def merged_with(self, extra_tokens: Iterable[str]) -> CanaryRegistry:
        return CanaryRegistry(self._tokens.union(extra_tokens))

    @classmethod
    def from_file(cls, path: Path) -> CanaryRegistry:
        """Load canary tokens from a JSON, YAML, or line-delimited text file."""
        raw = path.read_text(encoding="utf-8")
        tokens: list[str] = []
        suffix = path.suffix.lower()
        if suffix == ".json":
            data = json.loads(raw)
            tokens = _extract_canary_list(data)
        elif suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
            tokens = _extract_canary_list(data)
        else:
            for line in raw.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    tokens.append(stripped)
        return cls(DEFAULT_CANARIES.union(tokens))


def _extract_canary_list(data: object) -> list[str]:
    if isinstance(data, list) and all(isinstance(item, str) for item in data):
        return list(data)
    if isinstance(data, dict) and isinstance(data.get("canaries"), list):
        canaries = data["canaries"]
        if all(isinstance(item, str) for item in canaries):
            return list(canaries)
    raise ValueError("Canary registry file must be a list of strings or {'canaries': [...]}")


def find_canaries(text: str) -> list[tuple[str, int, int]]:
    """Return (token, start, end) for every EVALCANARY_* match in text."""
    return [(m.group(0), m.start(), m.end()) for m in CANARY_PATTERN.finditer(text)]
