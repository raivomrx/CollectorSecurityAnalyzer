"""Sensitive-data guard and evidence minimization."""

from __future__ import annotations

import re
from typing import Any

MAX_EVIDENCE_ITEMS = 64
MAX_TEXT_LENGTH = 512
SENSITIVE_PATTERNS = (
    (
        "AUTHORIZATION_HEADER",
        re.compile(
            r"\b(?:proxy-)?authorization\s*:\s*(?:ntlm|negotiate)\b"
            r"|\bauthorization\s*:\s*\S+"
            r"|\bbearer\s+[A-Za-z0-9._~+/=-]+",
            re.I,
        ),
    ),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)),
    ("PASSWORD", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+", re.I)),
    (
        "NETNTLM",
        re.compile(
            r"\bnetntlm(?:v[12])?\b"
            r"|\b(?:ntproofstr|ntchallengeresponse|lmchallengeresponse"
            r"|serverchallenge|sessionbasekey)\b"
            r"|ntlm\s+(?:response|hash|challenge)",
            re.I,
        ),
    ),
    ("CHALLENGE_RESPONSE", re.compile(r"\bchallenge[- ]response\b", re.I)),
    ("HASH_VALUE", re.compile(r"\b(?:hash|digest)\s*[:=]\s*[a-f0-9]{24,}", re.I)),
    ("ACCESS_TOKEN", re.compile(r"\b(?:access|refresh)[_-]?token\s*[:=]\s*\S+", re.I)),
    ("CLIENT_SECRET", re.compile(r"\bclient[_-]?secret\s*[:=]\s*\S+", re.I)),
    ("LOCAL_USER_PATH", re.compile(r"(?:[A-Z]:\\Users\\|/home/)[^\\/\s]+", re.I)),
    (
        "HASH_MATERIAL",
        re.compile(r"\b(?:nt|lm)\s*hash\b", re.I),
    ),
    (
        "DOMAIN_IDENTITY",
        re.compile(r"\b[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+\b"),
    ),
    (
        "USER_PASSWORD_PAIR",
        re.compile(
            r"\busername\s*:\s*password\b"
            r"|\b(?!sha256:)[A-Za-z][A-Za-z0-9._-]{1,63}:[^\s:/]{4,}\b",
            re.I,
        ),
    ),
    ("RAW_PACKET", re.compile(r"\braw\s+(?:packet|pcap)\b", re.I)),
)


class SensitiveEvidenceError(ValueError):
    """Report blocked credential-like or excessive evidence."""


def validate_evidence(evidence: list[dict[str, Any]]) -> None:
    """Reject sensitive, oversized, or structurally unsafe evidence."""

    if len(evidence) > MAX_EVIDENCE_ITEMS:
        raise SensitiveEvidenceError("Evidence item limit exceeded")
    _scan(evidence)


def validate_output_text(value: str) -> None:
    """Scan bounded process output without applying per-field text limits."""

    for category, pattern in SENSITIVE_PATTERNS:
        if pattern.search(value):
            raise SensitiveEvidenceError(
                f"Output blocked by sensitive category: {category}"
            )


def _scan(value: Any) -> None:
    """Recursively scan evidence values without logging matched content."""

    if isinstance(value, dict):
        for item in value.values():
            _scan(item)
        return
    if isinstance(value, list):
        for item in value:
            _scan(item)
        return
    if isinstance(value, str):
        if len(value) > MAX_TEXT_LENGTH:
            raise SensitiveEvidenceError("Evidence text limit exceeded")
        for category, pattern in SENSITIVE_PATTERNS:
            if pattern.search(value):
                raise SensitiveEvidenceError(
                    f"Evidence blocked by sensitive category: {category}"
                )
