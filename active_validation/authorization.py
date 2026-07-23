"""Explicit authorization loading and scope validation."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from active_validation.digest import sha256_digest
from active_validation.json_io import load_strict_json
from active_validation.enums import TestIdentityMode
from active_validation.models import (
    AuthorizationPermissions,
    AuthorizationScope,
    TestIdentity,
    ValidationAuthorization,
)

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
OPTIONAL_KEYS = {"permissions", "testIdentity"}
REQUIRED_SCOPE_KEYS = {"deviceIdentifiers", "validatorIds"}
OPTIONAL_SCOPE_KEYS = {
    "networkInterfaces",
    "allowedSourceAddresses",
    "allowedTargetAddresses",
    "allowedProtocols",
}
PERMISSION_KEYS = {
    "nameResolutionSpoofing",
    "authenticationChallenge",
    "temporaryListener",
    "temporaryFirewallChange",
    "credentialMaterialRetention",
    "credentialRelay",
    "hashCracking",
    "explicitCurrentUserTest",
    "machineAccountObservation",
}
TEST_IDENTITY_KEYS = {
    "mode",
    "identifier",
    "credentialReference",
    "authorizedForAuthenticationTest",
}
ALLOWED_PROTOCOLS = {"LLMNR", "NBT_NS", "SMB", "HTTP"}
SECURE_REFERENCE = re.compile(
    r"^(?:secure-runtime-reference|secret://[A-Za-z0-9._/-]+)$"
)


class AuthorizationError(ValueError):
    """Report invalid or out-of-scope active validation authorization."""


def load_authorization(
    path: str | Path,
    now: datetime | None = None,
) -> ValidationAuthorization:
    """Load and validate a time-limited authorization document."""

    data = load_strict_json(path)
    if (
        not REQUIRED_KEYS <= set(data)
        or set(data) - REQUIRED_KEYS - OPTIONAL_KEYS
    ):
        raise AuthorizationError("Authorization fields do not match schema 1.0")
    _reject_credential_material(data)
    if data["schemaVersion"] != "1.0" or data["authorized"] is not True:
        raise AuthorizationError("Authorization is not explicitly granted")
    scope = data["scope"]
    if (
        not isinstance(scope, dict)
        or not REQUIRED_SCOPE_KEYS <= set(scope)
        or set(scope) - REQUIRED_SCOPE_KEYS - OPTIONAL_SCOPE_KEYS
    ):
        raise AuthorizationError("Authorization scope is invalid")
    devices = _unique_strings(scope["deviceIdentifiers"], "deviceIdentifiers")
    validators = _unique_strings(scope["validatorIds"], "validatorIds")
    interfaces = _optional_unique_strings(
        scope.get("networkInterfaces", []), "networkInterfaces"
    )
    sources = _ip_addresses(
        scope.get("allowedSourceAddresses", []), "allowedSourceAddresses"
    )
    targets = _ip_addresses(
        scope.get("allowedTargetAddresses", []), "allowedTargetAddresses"
    )
    protocols = _optional_unique_strings(
        scope.get("allowedProtocols", []), "allowedProtocols"
    )
    unsupported_protocols = sorted(set(protocols) - ALLOWED_PROTOCOLS)
    if unsupported_protocols:
        raise AuthorizationError(
            "Unsupported authorized protocol: " + ", ".join(unsupported_protocols)
        )
    permissions = _parse_permissions(data.get("permissions"))
    test_identity = _parse_test_identity(data.get("testIdentity"), permissions)
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
        scope=AuthorizationScope(
            devices,
            validators,
            interfaces,
            sources,
            targets,
            protocols,
        ),
        authorized_by=_required_text(data["authorizedBy"], "authorizedBy"),
        authorized_at=data["authorizedAt"],
        expires_at=data["expiresAt"],
        purpose=_required_text(data["purpose"], "purpose"),
        digest=sha256_digest(data),
        permissions=permissions,
        test_identity=test_identity,
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


def _optional_unique_strings(value: Any, field_name: str) -> tuple[str, ...]:
    """Validate an optional unique string array."""

    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise AuthorizationError(f"{field_name} must be a string array")
    if len(value) != len(set(value)):
        raise AuthorizationError(f"{field_name} contains duplicate values")
    return tuple(value)


def _ip_addresses(value: Any, field_name: str) -> tuple[str, ...]:
    """Validate explicit unicast IP addresses."""

    addresses = _optional_unique_strings(value, field_name)
    try:
        parsed = tuple(ipaddress.ip_address(item) for item in addresses)
    except ValueError as error:
        raise AuthorizationError(f"{field_name} contains an invalid address") from error
    if any(item.is_unspecified or item.is_multicast for item in parsed):
        raise AuthorizationError(f"{field_name} must contain scoped unicast addresses")
    return addresses


def _parse_permissions(value: Any) -> AuthorizationPermissions:
    """Parse optional strict deep-validation permissions."""

    if value is None:
        return AuthorizationPermissions()
    if not isinstance(value, dict) or set(value) - PERMISSION_KEYS:
        raise AuthorizationError("Authorization permissions are invalid")
    if any(not isinstance(item, bool) for item in value.values()):
        raise AuthorizationError("Authorization permissions must be boolean")
    if any(value.get(key, False) for key in (
        "credentialMaterialRetention",
        "credentialRelay",
        "hashCracking",
    )):
        raise AuthorizationError("Retention, relay, and cracking are prohibited")
    return AuthorizationPermissions(
        name_resolution_spoofing=value.get("nameResolutionSpoofing", False),
        authentication_challenge=value.get("authenticationChallenge", False),
        temporary_listener=value.get("temporaryListener", False),
        temporary_firewall_change=value.get("temporaryFirewallChange", False),
        credential_material_retention=False,
        credential_relay=False,
        hash_cracking=False,
        explicit_current_user_test=value.get("explicitCurrentUserTest", False),
        machine_account_observation=value.get(
            "machineAccountObservation", False
        ),
    )


def _parse_test_identity(
    value: Any,
    permissions: AuthorizationPermissions,
) -> TestIdentity | None:
    """Parse a secret-reference-only test identity."""

    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != TEST_IDENTITY_KEYS:
        raise AuthorizationError("testIdentity fields are invalid")
    try:
        mode = TestIdentityMode(value["mode"])
    except (TypeError, ValueError) as error:
        raise AuthorizationError("testIdentity mode is invalid") from error
    if (
        mode == TestIdentityMode.EXPLICIT_CURRENT_USER_TEST
        and not permissions.explicit_current_user_test
    ):
        raise AuthorizationError("Current-user testing requires explicit permission")
    if (
        mode == TestIdentityMode.MACHINE_ACCOUNT_OBSERVATION
        and not permissions.machine_account_observation
    ):
        raise AuthorizationError("Machine-account observation requires permission")
    reference = _required_text(
        value["credentialReference"], "credentialReference"
    )
    if not SECURE_REFERENCE.fullmatch(reference):
        raise AuthorizationError("credentialReference is not a secure reference")
    if value["authorizedForAuthenticationTest"] is not True:
        raise AuthorizationError("Test identity is not authorized")
    return TestIdentity(
        mode=mode,
        identifier=_required_text(value["identifier"], "testIdentity.identifier"),
        credential_reference=reference,
        authorized_for_authentication_test=True,
    )


def _reject_credential_material(value: Any, path: str = "") -> None:
    """Reject password-like authorization fields without echoing their values."""

    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", key.casefold())
            if normalized in {"password", "passwd", "pwd", "secret", "ntlmresponse"}:
                raise AuthorizationError("Credential material is not allowed")
            _reject_credential_material(item, f"{path}.{key}")
    elif isinstance(value, list):
        for item in value:
            _reject_credential_material(item, path)


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
