"""Bounded protocol helpers for controlled Responder validation."""

from __future__ import annotations

import ipaddress
import re
import struct
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from active_validation.digest import sha256_digest

MARKER_PATTERN = re.compile(
    r"^(?:CSA-RSP-[A-F0-9]{8}-[A-F0-9]{6}|CSAR-[A-F0-9]{10})$"
)
MAX_PAYLOAD_BYTES = 65_536
MAX_HTTP_CONNECTIONS = 3
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


def build_transport_marker(run_id: str, protocol: str) -> str:
    """Return a protocol-compatible exact marker."""

    if protocol == "NBT_NS":
        return f"CSAR-{sha256_digest(run_id).upper()[:10]}"
    return build_run_marker(run_id)


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

    marker, transaction_id = parse_nbtns_query(query)
    if marker != expected_marker or not MARKER_PATTERN.fullmatch(marker):
        return None
    address = ipaddress.ip_address(response_address)
    if address.version != 4 or address.is_unspecified or address.is_multicast:
        raise ValueError("NBT-NS response address must be scoped IPv4")
    encoded_name = query[12:46]
    header = transaction_id + b"\x85\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    answer = (
        encoded_name
        + b"\x00\x20\x00\x01"
        + b"\x00\x00\x00\x1e"
        + b"\x00\x06\x00\x00"
        + address.packed
    )
    return header + answer


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


def parse_nbtns_query(payload: bytes) -> tuple[str, bytes]:
    """Parse one first-level encoded NetBIOS name query."""

    if not 50 <= len(payload) <= 512 or payload[12] != 32:
        raise ValueError("NBT-NS query is invalid")
    encoded = payload[13:45]
    if any(value < 65 or value > 80 for value in encoded):
        raise ValueError("NBT-NS name encoding is invalid")
    decoded = bytes(
        ((encoded[index] - 65) << 4) | (encoded[index + 1] - 65)
        for index in range(0, 32, 2)
    )
    name = decoded[:15].decode("ascii", errors="strict").rstrip()
    if payload[45] != 0 or payload[46:50] != b"\x00\x20\x00\x01":
        raise ValueError("NBT-NS question type is invalid")
    return name.upper(), payload[:2]


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
    """Build a valid in-memory Type 2 challenge bound to one run."""

    nonce = bytes.fromhex(sha256_digest(run_id)[:16])
    file_time = int(
        (datetime.now(timezone.utc).timestamp() + 11_644_473_600)
        * 10_000_000
    )
    target_info = (
        struct.pack("<HHQ", 7, 8, file_time)
        + struct.pack("<HH", 0, 0)
    )
    flags = 0xA2888235
    payload_offset = 56
    return (
        NTLM_SIGNATURE
        + struct.pack("<I", 2)
        + struct.pack("<HHI", 0, 0, payload_offset)
        + struct.pack("<I", flags)
        + nonce
        + b"\x00" * 8
        + struct.pack(
            "<HHI",
            len(target_info),
            len(target_info),
            payload_offset,
        )
        + b"\x0a\x00\x63\x45\x00\x00\x00\x0f"
        + target_info
    )


def parse_ntlm_authenticate_identity_hash(payload: bytes) -> str:
    """Hash the Type 3 identity without returning its plaintext value."""

    if parse_ntlm_message_type(payload) != "AUTHENTICATE":
        raise ValueError("NTLM authenticate message is required")
    offset = payload.find(NTLM_SIGNATURE)
    if offset < 0 or offset + 64 > len(payload):
        raise ValueError("NTLM authenticate message is incomplete")
    domain = _security_buffer(payload, offset + 28, offset)
    username = _security_buffer(payload, offset + 36, offset)
    flags = struct.unpack("<I", payload[offset + 60:offset + 64])[0]
    encoding = "utf-16-le" if flags & 0x00000001 else "ascii"
    try:
        domain_text = domain.decode(encoding, errors="strict")
        username_text = username.decode(encoding, errors="strict")
    except UnicodeError as error:
        raise ValueError("NTLM identity encoding is invalid") from error
    if not username_text or len(username_text) > 256 or len(domain_text) > 256:
        raise ValueError("NTLM identity is invalid")
    identity = (
        f"{domain_text}\\{username_text}" if domain_text else username_text
    )
    identity_hash = f"sha256:{sha256_digest(identity.strip().casefold())}"
    del identity, domain_text, username_text, domain, username
    return identity_hash


def _security_buffer(payload: bytes, offset: int, base_offset: int = 0) -> bytes:
    """Read one bounded NTLM security buffer."""

    if offset + 8 > len(payload):
        raise ValueError("NTLM security buffer is missing")
    length, maximum, value_offset = struct.unpack(
        "<HHI",
        payload[offset:offset + 8],
    )
    absolute_offset = base_offset + value_offset
    if length > maximum or absolute_offset + length > len(payload):
        raise ValueError("NTLM security buffer is outside the message")
    return payload[absolute_offset:absolute_offset + length]


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
    resolution_protocol = observation.get("nameResolutionProtocol")
    if interface not in scope.get("networkInterfaces", []):
        return None
    if source not in scope.get("allowedTargetAddresses", []):
        return None
    if listener not in scope.get("allowedSourceAddresses", []):
        return None
    if protocol not in scope.get("allowedProtocols", []):
        return None
    if (
        resolution_protocol is not None
        and resolution_protocol not in scope.get("allowedProtocols", [])
    ):
        return None
    if ipaddress.ip_address(listener).is_unspecified:
        return None
    response_count = int(observation.get("responseCount", 0))
    connection_count = int(observation.get("connectionCount", 0))
    payload_bytes = int(observation.get("payloadBytes", 0))
    if not 0 <= response_count <= 1:
        raise ValueError("Response count exceeds the one-shot limit")
    if not 0 <= connection_count <= MAX_HTTP_CONNECTIONS:
        raise ValueError("Connection count exceeds the bounded flow limit")
    if not 0 <= payload_bytes <= MAX_PAYLOAD_BYTES:
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
