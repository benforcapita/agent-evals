"""Redaction scanner rules per LLD §8."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


# Known secret key format rules (LLD §8).
# Order matters: more specific prefixes (e.g. sk-ant-) are checked before
# broader prefixes (e.g. sk-).
@dataclass(frozen=True)
class PatternRule:
    name: str
    pattern: re.Pattern[str]
    description: str


KNOWN_KEY_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        name="pem_block",
        pattern=re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
            r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        description="PEM private key block detected",
    ),
    PatternRule(
        name="anthropic_key",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
        description="Anthropic-style API key detected",
    ),
    PatternRule(
        name="openai_key",
        pattern=re.compile(
            r"\bsk-(?:proj-|svcacct-|admin-)?(?!ant-)[A-Za-z0-9_-]{20,}\b"
        ),
        description="OpenAI-style API key detected",
    ),
    PatternRule(
        name="xai_key",
        pattern=re.compile(r"\bxai-[A-Za-z0-9_-]{16,}\b"),
        description="xAI-style API key detected",
    ),
    PatternRule(
        name="github_token",
        pattern=re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})\b"
        ),
        description="GitHub token detected",
    ),
    PatternRule(
        name="linear_key",
        pattern=re.compile(r"\blin_api_[A-Za-z0-9_-]{16,}\b"),
        description="Linear API key detected",
    ),
    PatternRule(
        name="notion_token",
        pattern=re.compile(r"\b(?:secret_[A-Za-z0-9_-]{20,}|ntn_[A-Za-z0-9_-]{20,})\b"),
        description="Notion integration token detected",
    ),
    PatternRule(
        name="slack_token",
        pattern=re.compile(r"\bxox[a-zA-Z]-[A-Za-z0-9-]{10,}\b"),
        description="Slack token detected",
    ),
    PatternRule(
        name="aws_access_key",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        description="AWS access key ID detected",
    ),
    PatternRule(
        name="jwt",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        description="JWT token detected",
    ),
)

# Deny list of sensitive environment variable names (LLD §8).
DENY_LIST_ENV_VARS: frozenset[str] = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "XAI_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "LINEAR_API_KEY",
        "NOTION_TOKEN",
        "NOTION_API_KEY",
        "SLACK_TOKEN",
        "SLACK_BOT_TOKEN",
        "SLACK_APP_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "DATABASE_URL",
        "PRIVATE_KEY",
        "SECRET_KEY",
        "API_KEY",
        "API_SECRET",
        "ACCESS_TOKEN",
        "AUTH_TOKEN",
        "CLIENT_SECRET",
        "BEARER_TOKEN",
    }
)

# Matches dotenv/shell (`KEY=value`, `export KEY="value"`), YAML (`KEY: value`),
# and JSON (`"KEY": "value"`). Captures the env var name and the raw value span.
_ENV_NAMES_ALT = "|".join(sorted(DENY_LIST_ENV_VARS, key=len, reverse=True))
ENV_VAR_ASSIGNMENT_PATTERN = re.compile(
    rf"""(?x)
    (?<![A-Za-z0-9_])
    (?:"(?P<json_name>{_ENV_NAMES_ALT})"\s*:\s*(?P<json_val>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,\}}\]]+)
    |(?P<kv_name>{_ENV_NAMES_ALT})\s*[:=]\s*(?P<kv_val>"[^"\r\n]*"|'[^'\r\n]*'|[^\s#,\}}\]]+))
    """
)

# High-entropy token parameters (LLD §8: Shannon entropy > 4.0 on 24+ char tokens).
HIGH_ENTROPY_MIN_LENGTH = 24
HIGH_ENTROPY_THRESHOLD = 4.0
HIGH_ENTROPY_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{24,}=*)(?![A-Za-z0-9+/_=-])"
)

URL_PATTERN = re.compile(r"https?://[^\s\"'<>`]+")
REDACTED_MARKER_PATTERN = re.compile(r"\[REDACTED:[a-z0-9_]+\]")
ENV_REF_VALUE_PATTERN = re.compile(
    r"^(?:\$\{?[A-Z][A-Z0-9_]*\}?|process\.env\.[A-Z][A-Z0-9_]*|os\.environ(?:\.get)?\[?.*)$"
)
SAFE_LITERAL_VALUES = frozenset({"", "null", "none", "true", "false", "redacted", "<redacted>"})
FILE_PATH_EXTENSIONS = (
    ".py",
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".ts",
    ".js",
    ".lock",
)

ALL_RULE_NAMES: tuple[str, ...] = (
    *(rule.name for rule in KNOWN_KEY_RULES),
    "high_entropy_token",
    "env_var_assignment",
    "canary_leak",
    "unregistered_canary",
)


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_file_path(token: str) -> bool:
    """Return True if token looks like a repository/filesystem path rather than a secret."""
    if "/" not in token:
        return False
    lower = token.lower()
    return lower.endswith(FILE_PATH_EXTENSIONS) or token.startswith(("/", "./", "../"))
