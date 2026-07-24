"""Network scope validation for the local Assessment Console."""

from __future__ import annotations

import ipaddress

from csa_console.models import AssessmentSession


def source_is_allowed(session: AssessmentSession, source_address: str) -> bool:
    """Return whether a source address is permitted by the session."""

    try:
        address = ipaddress.ip_address(source_address)
    except ValueError:
        return False
    if source_address in session.allowed_source_addresses:
        return True
    if not session.allowed_source_addresses and not session.allowed_source_networks:
        return address.is_loopback and ipaddress.ip_address(
            session.listen_address
        ).is_loopback
    for value in session.allowed_source_networks:
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


def validate_listen_address(address: str, allow_wildcard: bool = False) -> None:
    """Reject wildcard and invalid bind addresses unless explicitly allowed."""

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as error:
        raise ValueError("Listen address must be a concrete IP address") from error
    if parsed.is_unspecified and not allow_wildcard:
        raise ValueError("Wildcard listen address requires explicit opt-in")
