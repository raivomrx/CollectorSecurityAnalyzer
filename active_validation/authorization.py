"""Explicit authorization loading and scope validation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from active_validation.digest import sha256_digest
from active_validation.json_io import load_strict_json
from active_validation.models import AuthorizationScope, ValidationAuthorization

REQUIRED_KEYS = {
    "schemaVersion",
    "authorized",
    "assessmentId",
    "scope",
    "authorizedBy",
    "authorizedAt",
    "expiresAt",
    "purpose",
}
SCOPE_KEYS = {"deviceIdentifiers", "validatorIds"}


class AuthorizationError(ValueError):
    """Report invalid or out-of-scope active validation authorization."""


def load_authorization(
    path: str | Path,
    now: datetime | None = None,
) -> ValidationAuthorization:
    """Load and validate a time-limited authorization document."""

    data = load_strict_json(path)
    if set(data) != REQUIRED_KEYS:
        raise AuthorizationError("Authorization fields do not match schema 1.0")
    if data["schemaVersion"] != "1.0" or data["authorized"] is not True:
        raise AuthorizationError("Authorization is not explicitly granted")
    scope = data["scope"]
    if not isinstance(scope, dict) or set(scope) != SCOPE_KEYS:
        raise AuthorizationError("Authorization scope is invalid")
    devices = _unique_strings(scope["deviceIdentifiers"], "deviceIdentifiers")
    validators = _unique_strings(scope["validatorIds"], "validatorIds")
    assessment_id = _required_text(data["assessmentId"], "assessmentId")
    authorized_at = _parse_timestamp(data["authorizedAt"], "authorizedAt")
    expires_at = _parse_timestamp(data["expiresAt"], "expiresAt")
    current = now or datetime.now(timezone.utc)
    if expires_at <= current:
        raise AuthorizationError("Authorization has expired")
    if authorized_at > current:
        raise AuthorizationError("Authorization is not yet valid")
    if expires_at <= authorized_at:
        raise AuthorizationError("Authorization expiry precedes authorization time")
    return ValidationAuthorization(
        schema_version="1.0",
        authorized=True,
        assessment_id=assessment_id,
        scope=AuthorizationScope(devices, validators),
        authorized_by=_required_text(data["authorizedBy"], "authorizedBy"),
        authorized_at=data["authorizedAt"],
        expires_at=data["expiresAt"],
        purpose=_required_text(data["purpose"], "purpose"),
        digest=sha256_digest(data),
    )


def require_scope(
    authorization: ValidationAuthorization,
    device_identifier: str,
    validator_ids: list[str],
    assessment_id: str | None = None,
) -> None:
    """Require the requested device, assessment, and validators to be authorized."""

    if assessment_id is not None and authorization.assessment_id != assessment_id:
        raise AuthorizationError("Assessment ID does not match authorization")
    if device_identifier not in authorization.scope.device_identifiers:
        raise AuthorizationError("Device is outside authorization scope")
    unauthorized = sorted(set(validator_ids) - set(authorization.scope.validator_ids))
    if unauthorized:
        raise AuthorizationError(
            "Validators outside authorization scope: " + ", ".join(unauthorized)
        )


def _unique_strings(value: Any, field_name: str) -> tuple[str, ...]:
    """Validate a non-empty unique string array."""

    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise AuthorizationError(f"{field_name} must be a non-empty string array")
    if len(value) != len(set(value)):
        raise AuthorizationError(f"{field_name} contains duplicate values")
    return tuple(value)


def _required_text(value: Any, field_name: str) -> str:
    """Validate a required bounded text field."""

    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise AuthorizationError(f"{field_name} is invalid")
    return value


def _parse_timestamp(value: Any, field_name: str) -> datetime:
    """Parse one timezone-aware ISO-8601 timestamp."""

    if not isinstance(value, str):
        raise AuthorizationError(f"{field_name} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuthorizationError(f"{field_name} must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise AuthorizationError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)
