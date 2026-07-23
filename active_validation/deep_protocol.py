"""Bounded protocol helpers for controlled Responder validation."""

from __future__ import annotations

import ipaddress
from active_validation.digest import sha256_digest
import re
import struct
from dataclasses import dataclass
from typing import Any

MARKER_PATTERN = re.compile(r"^CSA-RSP-[A-F0-9]{8}-[A-F0-9]{6}$")
MAX_PAYLOAD_BYTES = 65_536
NTLM_SIGNATURE = b"NTLMSSP\x00"
NTLM_MESSAGE_TYPES = {
    1: "NEGOTIATE",
    2: "CHALLENGE",
    3: "AUTHENTICATE",
}


def build_run_marker(run_id: str) -> str:
    """Return the exact controlled marker for one run."""

    normalized = sha256_digest(run_id).upper()
    return f"CSA-RSP-{normalized[:8]}-{normalized[8:14]}"


@dataclass(slots=True, frozen=True)
class ScopedTransportSignal:
    """Represent a scope-checked transport event without raw payload."""

    marker_query_observed: bool
    response_sent: bool
    listener_operational: bool
    connection_observed: bool
    authentication_challenge_issued: bool
    authentication_attempt_observed: bool
    protocol: str | None
    message_types_observed: tuple[str, ...]
    test_identity_matched: bool
    sufficient_observation_window: bool
    ntlm_outbound_blocked: bool
    client_signing_required: bool
    protocol_parser_verified: bool


def build_llmnr_response(
    query: bytes,
    expected_marker: str,
    response_address: str,
) -> bytes | None:
    """Build one exact-marker LLMNR A response or ignore the query."""

    marker, transaction_id = parse_name_query(query)
    if marker != expected_marker or not MARKER_PATTERN.fullmatch(marker):
        return None
    address = ipaddress.ip_address(response_address)
    if address.version != 4 or address.is_unspecified or address.is_multicast:
        raise ValueError("LLMNR response address must be scoped IPv4")
    question = query[12:]
    header = transaction_id + b"\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" + address.packed
    return header + question + answer


def build_nbtns_response(
    query: bytes,
    expected_marker: str,
    response_address: str,
) -> bytes | None:
    """Build one exact-marker NBT-NS response or ignore the query."""

    marker, transaction_id = parse_name_query(query)
    if marker != expected_marker or not MARKER_PATTERN.fullmatch(marker):
        return None
    address = ipaddress.ip_address(response_address)
    if address.version != 4 or address.is_unspecified or address.is_multicast:
        raise ValueError("NBT-NS response address must be scoped IPv4")
    header = transaction_id + b"\x85\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    return header + query[12:] + b"\x00\x00\x00\x1e\x00\x06\x00\x00" + address.packed


def parse_name_query(payload: bytes) -> tuple[str, bytes]:
    """Parse one bounded DNS-label query used by the controlled harness."""

    if not 17 <= len(payload) <= 512:
        raise ValueError("Name-resolution payload size is invalid")
    transaction_id = payload[:2]
    question_count = struct.unpack("!H", payload[4:6])[0]
    if question_count != 1:
        raise ValueError("Exactly one marker question is required")
    cursor = 12
    labels: list[str] = []
    while cursor < len(payload):
        size = payload[cursor]
        cursor += 1
        if size == 0:
            break
        if size > 63 or cursor + size > len(payload):
            raise ValueError("Invalid query label")
        labels.append(payload[cursor:cursor + size].decode("ascii"))
        cursor += size
    if cursor + 4 > len(payload):
        raise ValueError("Query type is missing")
    return ".".join(labels).upper(), transaction_id


def parse_ntlm_message_type(payload: bytes) -> str:
    """Return an NTLM message label without retaining any message fields."""

    if not 12 <= len(payload) <= MAX_PAYLOAD_BYTES:
        raise ValueError("Authentication payload size is invalid")
    offset = payload.find(NTLM_SIGNATURE)
    if offset < 0 or offset + 12 > len(payload):
        raise ValueError("NTLM signature is unavailable")
    message_type = struct.unpack("<I", payload[offset + 8:offset + 12])[0]
    try:
        return NTLM_MESSAGE_TYPES[message_type]
    except KeyError as error:
        raise ValueError("NTLM message type is unsupported") from error


def build_ephemeral_ntlm_challenge(run_id: str) -> bytes:
    """Build an in-memory Type 2 challenge bound to one run."""

    nonce = bytes.fromhex(sha256_digest(run_id)[:16])
    return (
        NTLM_SIGNATURE
        + struct.pack("<I", 2)
        + b"\x00" * 8
        + struct.pack("<I", 0x00008201)
        + nonce
        + b"\x00" * 16
    )


def scoped_transport_signal(
    observation: dict[str, Any],
    expected_marker: str,
    scope: dict[str, Any],
) -> ScopedTransportSignal | None:
    """Validate a minimized harness signal against exact authorization scope."""

    if observation.get("queryMarker") != expected_marker:
        return None
    interface = observation.get("networkInterface")
    source = observation.get("sourceAddress")
    listener = observation.get("listenerAddress")
    protocol = observation.get("protocol")
    if interface not in scope.get("networkInterfaces", []):
        return None
    if source not in scope.get("allowedTargetAddresses", []):
        return None
    if listener not in scope.get("allowedSourceAddresses", []):
        return None
    if protocol not in scope.get("allowedProtocols", []):
        return None
    if ipaddress.ip_address(listener).is_unspecified:
        return None
    if int(observation.get("responseCount", 0)) > 1:
        raise ValueError("Response count exceeds the one-shot limit")
    if int(observation.get("connectionCount", 0)) > 1:
        raise ValueError("Connection count exceeds the one-shot limit")
    if int(observation.get("payloadBytes", 0)) > MAX_PAYLOAD_BYTES:
        raise ValueError("Authentication payload exceeds the limit")
    messages = tuple(observation.get("messageTypesObserved", []))
    if any(item not in {"NEGOTIATE", "CHALLENGE", "AUTHENTICATE"} for item in messages):
        raise ValueError("Unexpected authentication message type")
    return ScopedTransportSignal(
        marker_query_observed=observation.get("markerQueryObserved") is True,
        response_sent=observation.get("responseSent") is True,
        listener_operational=observation.get("listenerOperational") is True,
        connection_observed=observation.get("connectionObserved") is True,
        authentication_challenge_issued=(
            observation.get("authenticationChallengeIssued") is True
        ),
        authentication_attempt_observed=(
            observation.get("authenticationAttemptObserved") is True
        ),
        protocol=protocol,
        message_types_observed=messages,
        test_identity_matched=observation.get("testIdentityMatched") is True,
        sufficient_observation_window=(
            observation.get("sufficientObservationWindow") is True
        ),
        ntlm_outbound_blocked=observation.get("ntlmOutboundBlocked") is True,
        client_signing_required=observation.get("clientSigningRequired") is True,
        protocol_parser_verified=(
            observation.get("protocolParserVerified") is True
        ),
    )
