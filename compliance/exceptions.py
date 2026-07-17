"""Compliance engine exceptions."""

from __future__ import annotations


class ComplianceError(Exception):
    """Base compliance exception."""


class ComplianceDefinitionError(ComplianceError):
    """Raised when framework/profile definitions are invalid."""


class ComplianceProfileError(ComplianceError):
    """Raised when profile resolution fails."""
