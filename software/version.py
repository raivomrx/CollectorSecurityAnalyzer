"""Version parsing and comparison helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from software.models import ParsedVersion

_VERSION_PART_RE = re.compile(r"\d+")
_NUMERIC = re.compile(r"[0-9]{1,12}(?:\.[0-9]{1,12}){0,3}")
_CPYTHON = re.compile(r"(3\.[0-9]{1,2}\.[0-9]{1,2})(?:(a|b|rc)([0-9]{1,2}))?")
_MSI = re.compile(r"(3\.[0-9]{1,2})\.([0-9]{3,5})(?:\.0)?")
_PYTHON_TITLE = re.compile(r"Python (3\.[0-9]{1,2}\.[0-9]{1,2}(?:(?:a|b|rc)[0-9]{1,2})?)(?: Core Interpreter)?(?: \((?:32-bit|64-bit|ARM64)\))?", re.I)
_SEMVER = re.compile(r"((?:0|[1-9][0-9]{0,11})(?:\.(?:0|[1-9][0-9]{0,11})){2})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
_OPENSSL = re.compile(r"(1\.[0-9]{1,3}\.[0-9]{1,3})([a-z]{0,4})")


@dataclass(frozen=True, slots=True)
class VersionComparison:
    order: int | None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class VersionEvidence:
    raw: str
    interpreted: str | None
    scheme: str
    source: str
    reason: str | None = None


def version_evidence(vendor: str, product: str, version: str) -> VersionEvidence:
    """Use raw publisher/title evidence for product-specific version schemes."""

    if not version:
        return VersionEvidence(version, None, "numeric", "DISPLAY_VERSION", "VERSION_UNAVAILABLE")
    if vendor.casefold() == "python software foundation" and re.match(r"python(?:\s|$)", product, re.I):
        title = _PYTHON_TITLE.fullmatch(product)
        named = title[1].lower() if title else None
        msi = _MSI.fullmatch(version)
        if msi:
            micro, release = divmod(int(msi[2]), 1000)
            # CPython PCbuild/python.props and Tools/msi/msi.props at v3.12.4/v3.14.2.
            level, serial = divmod(release, 10)
            suffix = {10: "a", 11: "b", 12: "rc"}.get(level)
            decoded = f"{msi[1]}.{micro}"
            if suffix:
                decoded += f"{suffix}{serial}"
            if not named or not (suffix or release == 150) or not _CPYTHON.fullmatch(decoded):
                return VersionEvidence(version, None, "cpython", "CPYTHON_WINDOWS_MSI", "VERSION_SCHEME_UNSUPPORTED")
            if decoded != named:
                return VersionEvidence(version, None, "cpython", "CPYTHON_WINDOWS_MSI", "VERSION_SOURCE_CONFLICT")
            return VersionEvidence(version, decoded, "cpython", "CPYTHON_WINDOWS_MSI")
        if title:
            if not _CPYTHON.fullmatch(version):
                return VersionEvidence(version, None, "cpython", "DISPLAY_VERSION", "VERSION_SCHEME_UNSUPPORTED")
            if version != named:
                return VersionEvidence(version, None, "cpython", "DISPLAY_VERSION", "VERSION_SOURCE_CONFLICT")
            return VersionEvidence(version, version, "cpython", "DISPLAY_VERSION")
    if vendor.casefold() in {"openssl", "openssl software foundation"} and product.casefold() == "openssl" and _OPENSSL.fullmatch(version):
        return VersionEvidence(version, version, "openssl", "OPENSSL_LEGACY_RELEASE")
    return VersionEvidence(version, version, "numeric", "DISPLAY_VERSION")


def compare_applicability_versions(left: Any, right: Any, scheme: str = "numeric") -> VersionComparison:
    """Return an order only within a supported, explicitly selected scheme."""

    if not isinstance(left, str) or not isinstance(right, str) or not left or not right:
        return VersionComparison(None, "VERSION_INCOMPARABLE")
    if scheme == "numeric":
        if not _NUMERIC.fullmatch(left) or not _NUMERIC.fullmatch(right):
            return VersionComparison(None, "VERSION_SCHEME_UNSUPPORTED")
        lhs, rhs = (tuple(map(int, value.split("."))) for value in (left, right))
        mixed_build_width = (len(lhs) == 4) != (len(rhs) == 4)
        lhs, rhs = (parts + (0,) * (4 - len(parts)) for parts in (lhs, rhs))
        if mixed_build_width and lhs[:3] == rhs[:3] and lhs[3] != rhs[3]:
            return VersionComparison(None, "VERSION_INCOMPARABLE")
    else:
        lhs, rhs = (_scheme_key(value, scheme) for value in (left, right))
        if lhs is None or rhs is None:
            return VersionComparison(None, "VERSION_SCHEME_UNSUPPORTED")
    return VersionComparison((lhs > rhs) - (lhs < rhs))


def _scheme_key(value: str, scheme: str) -> tuple | None:
    if scheme == "cpython" and (match := _CPYTHON.fullmatch(value)):
        return tuple(map(int, match[1].split("."))), {"a": 0, "b": 1, "rc": 2, None: 3}[match[2]], int(match[3] or 0)
    if scheme == "openssl" and (match := _OPENSSL.fullmatch(value)):
        return tuple(map(int, match[1].split("."))), len(match[2]), match[2]
    if scheme == "semver" and len(value) <= 128 and (match := _SEMVER.fullmatch(value)):
        pre = match[2].split(".") if match[2] else []
        if any(token.isdigit() and len(token) > 1 and token.startswith("0") for token in pre):
            return None
        return tuple(map(int, match[1].split("."))), not pre, tuple(
            (0, int(token)) if token.isdigit() else (1, token) for token in pre
        )
    return None


def parse_version(value: Any) -> ParsedVersion:
    """Parse a software version into a comparable normalized form."""

    original = "" if value is None else str(value).strip()
    parts = tuple(int(part) for part in _VERSION_PART_RE.findall(original))
    normalized = ".".join(str(part) for part in parts)
    return ParsedVersion(original=original, parts=parts, normalized=normalized)


def normalize_version(value: Any) -> str:
    """Return the normalized software version string."""

    return parse_version(value).normalized


def compare_versions(left: Any, right: Any) -> int:
    """Compare two versions and return -1, 0, or 1."""

    parsed_left = parse_version(left)
    parsed_right = parse_version(right)
    if parsed_left < parsed_right:
        return -1
    if parsed_left > parsed_right:
        return 1
    return 0
