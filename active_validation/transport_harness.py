"""Self-hosted Windows one-shot Responder transport harness."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

from active_validation.deep_protocol import (
    MAX_PAYLOAD_BYTES,
    build_ephemeral_ntlm_challenge,
    build_llmnr_response,
    build_nbtns_response,
    parse_ntlm_authenticate_identity_hash,
    parse_ntlm_message_type,
)
from active_validation.digest import canonical_json, sha256_digest
from active_validation.json_io import load_strict_json

SCRIPT_DIR = Path(__file__).resolve().parent / "powershell"
TRUSTED_SCRIPT_HASHES = {
    "Manage-ResponderFirewall.ps1":
        "e1e3cc1e780a0add0e158c656114b5c8a80cdeeab8ab852ef757392ca4b94dac",
    "Invoke-ResponderMarkerLookup.ps1":
        "66860d53adcae3e3ecb750a81b55c50fac0064c683e921f925faaecc805e875e",
}
REQUIRED_INPUT_KEYS = {
    "schemaVersion",
    "runId",
    "planDigest",
    "authorizationDigest",
    "marker",
    "networkInterface",
    "listenerAddress",
    "targetAddress",
    "nameResolutionProtocol",
    "listenerPort",
    "remoteComputer",
    "expectedIdentityHash",
    "timeoutSeconds",
    "firewallProfile",
    "firewallStatePath",
}


def main() -> None:
    """Run one live transport and emit only an attested safe observation."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()
    if (
        input_path.parent != output_path.parent
        or not input_path.name.startswith("harness-input-")
        or not output_path.name.startswith("harness-output-")
    ):
        raise SystemExit(2)
    data = load_strict_json(input_path)
    key = _attestation_key()
    try:
        config = _validate_input(data, input_path.parent)
        observation = _run(config)
    except Exception:
        observation = _error_observation(data)
    document = {
        "observation": observation,
        "attestation": hmac.new(
            key,
            canonical_json(observation).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest(),
    }
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(output_path)


def cleanup_firewall_state(state_path: str | Path) -> bool:
    """Remove tracked harness firewall rules and verify final absence."""

    path = Path(state_path)
    if not path.exists():
        return True
    try:
        state = load_strict_json(path)
        rules = state.get("rules", [])
        if not isinstance(rules, list):
            return False
        completed = True
        for rule in rules:
            if not isinstance(rule, dict):
                completed = False
                continue
            name = str(rule.get("name", ""))
            if not name.startswith(f"CSA-VALIDATION-{state.get('runId', '')}-"):
                completed = False
                continue
            _firewall_script("Remove", name)
            if _firewall_exists(name):
                completed = False
        if completed:
            path.unlink(missing_ok=True)
        return completed
    except (OSError, TypeError, ValueError):
        return False


def _run(config: dict[str, Any]) -> dict[str, Any]:
    """Execute exact-marker resolution and one HTTP authentication exchange."""

    started = monotonic()
    timeout = int(config["timeoutSeconds"])
    firewall_state = Path(config["firewallStatePath"])
    resolution_port = (
        5355 if config["nameResolutionProtocol"] == "LLMNR" else 137
    )
    resolution_suffix = (
        "LLMNR"
        if config["nameResolutionProtocol"] == "LLMNR"
        else "NBTNS"
    )
    rule_prefix = f"CSA-VALIDATION-{config['runId']}"
    rules = [
        {
            "name": f"{rule_prefix}-{resolution_suffix}",
            "protocol": "UDP",
            "port": resolution_port,
            "created": False,
        },
        {
            "name": f"{rule_prefix}-HTTP",
            "protocol": "TCP",
            "port": int(config["listenerPort"]),
            "created": False,
        },
    ]
    _write_firewall_state(firewall_state, config["runId"], rules)
    observation = _base_observation(config)
    udp_socket: socket.socket | None = None
    http_socket: socket.socket | None = None
    trigger: subprocess.Popen[bytes] | None = None
    try:
        for rule in rules:
            _firewall_script(
                "Add",
                rule["name"],
                protocol=rule["protocol"],
                port=rule["port"],
                local_address=config["listenerAddress"],
                remote_address=config["targetAddress"],
                network_interface=config["networkInterface"],
                profile=config["firewallProfile"],
            )
            rule["created"] = True
            _write_firewall_state(firewall_state, config["runId"], rules)
        observation["firewallRuleCreated"] = True
        udp_socket = _resolution_listener(config, resolution_port)
        http_socket = _http_listener(config)
        observation["listenerOperational"] = True
        trigger = _start_trigger(config)
        observation["triggerProcessStarted"] = True
        deadline = started + timeout
        _observe_resolution(udp_socket, config, observation, deadline)
        _observe_http(http_socket, config, observation, deadline)
        observation["sufficientObservationWindow"] = (
            monotonic() >= deadline
            or observation["authenticationAttemptObserved"]
        )
        observation["protocolParserVerified"] = all(
            item in observation["messageTypesObserved"]
            for item in ("NEGOTIATE", "CHALLENGE", "AUTHENTICATE")
        )
    finally:
        if trigger is not None:
            try:
                trigger.wait(timeout=2)
            except subprocess.TimeoutExpired:
                trigger.kill()
                trigger.wait(timeout=2)
        if udp_socket is not None:
            udp_socket.close()
        if http_socket is not None:
            http_socket.close()
        observation["cleanupCompleted"] = cleanup_firewall_state(firewall_state)
        observation["firewallRuleRemoved"] = observation["cleanupCompleted"]
    return observation


def _resolution_listener(
    config: dict[str, Any],
    port: int,
) -> socket.socket:
    """Bind one UDP name-resolution socket to the authorized interface IP."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.settimeout(0.25)
    listener.bind((config["listenerAddress"], port))
    if config["nameResolutionProtocol"] == "LLMNR":
        membership = (
            socket.inet_aton("224.0.0.252")
            + socket.inet_aton(config["listenerAddress"])
        )
        listener.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            membership,
        )
    else:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    return listener


def _http_listener(config: dict[str, Any]) -> socket.socket:
    """Bind a one-shot TCP listener to one authorized local address."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((config["listenerAddress"], int(config["listenerPort"])))
    listener.listen(1)
    listener.settimeout(0.25)
    return listener


def _observe_resolution(
    listener: socket.socket,
    config: dict[str, Any],
    observation: dict[str, Any],
    deadline: float,
) -> None:
    """Wait for one exact marker query and send at most one response."""

    while monotonic() < deadline and observation["responseCount"] == 0:
        try:
            payload, address = listener.recvfrom(512)
        except socket.timeout:
            continue
        if address[0] != config["targetAddress"]:
            observation["scopeMismatchCount"] += 1
            continue
        try:
            if config["nameResolutionProtocol"] == "LLMNR":
                response = build_llmnr_response(
                    payload,
                    config["marker"],
                    config["listenerAddress"],
                )
            else:
                response = build_nbtns_response(
                    payload,
                    config["marker"],
                    config["listenerAddress"],
                )
        except (UnicodeError, ValueError):
            response = None
        if response is None:
            observation["scopeMismatchCount"] += 1
            continue
        observation["markerQueryObserved"] = True
        listener.sendto(response, address)
        observation["responseSent"] = True
        observation["responseCount"] = 1


def _observe_http(
    listener: socket.socket,
    config: dict[str, Any],
    observation: dict[str, Any],
    deadline: float,
) -> None:
    """Observe one authorized HTTP NTLM exchange without retaining its tokens."""

    connection: socket.socket | None = None
    while monotonic() < deadline and connection is None:
        try:
            candidate, address = listener.accept()
        except socket.timeout:
            continue
        if address[0] != config["targetAddress"]:
            observation["scopeMismatchCount"] += 1
            candidate.close()
            continue
        connection = candidate
        observation["connectionObserved"] = True
        observation["connectionCount"] = 1
        observation["sourceEndpointHash"] = (
            f"sha256:{sha256_digest(address[0])}"
        )
    if connection is None:
        return
    with connection:
        connection.settimeout(2)
        for _ in range(4):
            token = _read_authentication_token(connection)
            if token is None:
                _send_http(connection, 401, "NTLM")
                continue
            raw = bytearray(token)
            observation["payloadBytes"] += len(raw)
            try:
                message_type = parse_ntlm_message_type(raw)
                if message_type not in observation["messageTypesObserved"]:
                    observation["messageTypesObserved"].append(message_type)
                if message_type == "NEGOTIATE":
                    challenge = build_ephemeral_ntlm_challenge(config["runId"])
                    observation["messageTypesObserved"].append("CHALLENGE")
                    observation["authenticationChallengeIssued"] = True
                    _send_http(
                        connection,
                        401,
                        "NTLM " + base64.b64encode(challenge).decode("ascii"),
                    )
                elif message_type == "AUTHENTICATE":
                    observed_hash = parse_ntlm_authenticate_identity_hash(raw)
                    observation["authenticationAttemptObserved"] = True
                    observation["testIdentityMatched"] = (
                        hmac.compare_digest(
                            observed_hash,
                            config["expectedIdentityHash"],
                        )
                    )
                    _send_http(connection, 200, None)
                    return
            finally:
                raw[:] = b"\x00" * len(raw)
                del raw, token


def _read_authentication_token(connection: socket.socket) -> bytes | None:
    """Read one bounded HTTP request and return only its decoded auth token."""

    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = connection.recv(4096)
        if not chunk:
            return None
        buffer.extend(chunk)
        if len(buffer) > 32_768:
            raise ValueError("HTTP header exceeded the harness limit")
    header_end = buffer.index(b"\r\n\r\n")
    lines = bytes(buffer[:header_end]).split(b"\r\n")
    token: bytes | None = None
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() in {
            b"authorization",
            b"proxy-authorization",
        }:
            scheme, separator, encoded = value.strip().partition(b" ")
            if (
                separator
                and scheme.lower() in {b"ntlm", b"negotiate"}
                and len(encoded) <= MAX_PAYLOAD_BYTES * 2
            ):
                token = base64.b64decode(encoded, validate=True)
            break
    buffer[:] = b"\x00" * len(buffer)
    return token


def _send_http(
    connection: socket.socket,
    status: int,
    authenticate: str | None,
) -> None:
    """Send one bounded HTTP response."""

    reason = "OK" if status == 200 else "Unauthorized"
    lines = [
        f"HTTP/1.1 {status} {reason}",
        "Content-Length: 0",
        "Connection: keep-alive" if status == 401 else "Connection: close",
    ]
    if authenticate is not None:
        lines.append(f"WWW-Authenticate: {authenticate}")
    connection.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))


def _start_trigger(config: dict[str, Any]) -> subprocess.Popen[bytes]:
    """Start the packaged marker trigger under the runner's test identity."""

    script = _trusted_script("Invoke-ResponderMarkerLookup.ps1")
    return subprocess.Popen(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Marker",
            config["marker"],
            "-ListenerPort",
            str(config["listenerPort"]),
            "-NameResolutionProtocol",
            config["nameResolutionProtocol"],
            "-RemoteComputer",
            config["remoteComputer"],
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=(
            subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        ),
        env=_child_environment(),
    )


def _firewall_script(
    action: str,
    rule_name: str,
    protocol: str = "TCP",
    port: int = 8080,
    local_address: str = "",
    remote_address: str = "",
    network_interface: str = "",
    profile: str = "Private",
) -> None:
    """Invoke the digest-verified firewall helper without shell expansion."""

    script = _trusted_script("Manage-ResponderFirewall.ps1")
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        "-Action",
        action,
        "-RuleName",
        rule_name,
    ]
    if action == "Add":
        command.extend([
            "-Protocol",
            protocol,
            "-LocalPort",
            str(port),
            "-LocalAddress",
            local_address,
            "-RemoteAddress",
            remote_address,
            "-NetworkInterface",
            network_interface,
            "-Profile",
            profile,
            "-Program",
            sys.executable,
        ])
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        env=_child_environment(),
    )
    if completed.returncode != 0:
        raise RuntimeError("Scoped firewall operation failed")


def _firewall_exists(rule_name: str) -> bool:
    """Return whether an exact tracked firewall rule remains."""

    script = _trusted_script("Manage-ResponderFirewall.ps1")
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Action",
            "Exists",
            "-RuleName",
            rule_name,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        env=_child_environment(),
    )
    return completed.returncode == 3


def _trusted_script(name: str) -> Path:
    """Return one canonical packaged script after SHA-256 verification."""

    script = (SCRIPT_DIR / name).resolve()
    if script.parent != SCRIPT_DIR.resolve() or name not in TRUSTED_SCRIPT_HASHES:
        raise RuntimeError("Transport harness script is not trusted")
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    if not hmac.compare_digest(digest, TRUSTED_SCRIPT_HASHES[name]):
        raise RuntimeError("Transport harness script digest mismatch")
    return script


def _validate_input(
    data: dict[str, Any],
    run_directory: Path,
) -> dict[str, Any]:
    """Validate exact-scope harness input without accepting broad defaults."""

    if set(data) != REQUIRED_INPUT_KEYS or data["schemaVersion"] != "1.0":
        raise ValueError("Transport harness input fields are invalid")
    if data["nameResolutionProtocol"] not in {"LLMNR", "NBT_NS"}:
        raise ValueError("Transport protocol is invalid")
    if data["firewallProfile"] not in {"Domain", "Private", "Public"}:
        raise ValueError("Firewall profile is invalid")
    for key in ("listenerAddress", "targetAddress"):
        address = socket.inet_aton(str(data[key]))
        if address == b"\x00\x00\x00\x00":
            raise ValueError("Unscoped listener address is prohibited")
    port = int(data["listenerPort"])
    timeout = int(data["timeoutSeconds"])
    if not 1024 <= port <= 65535 or not 5 <= timeout <= 60:
        raise ValueError("Transport limits are invalid")
    if not str(data["marker"]).startswith(("CSA-RSP-", "CSAR-")):
        raise ValueError("Transport marker is invalid")
    if not str(data["expectedIdentityHash"]).startswith("sha256:"):
        raise ValueError("Expected identity hash is invalid")
    state_path = Path(str(data["firewallStatePath"])).resolve()
    if (
        state_path.parent != run_directory
        or not state_path.name.startswith("firewall-state-")
        or state_path.suffix != ".json"
    ):
        raise ValueError("Firewall recovery state path is invalid")
    return data


def _base_observation(config: dict[str, Any]) -> dict[str, Any]:
    """Return a credential-safe observation bound to reviewed digests."""

    return {
        "runId": config["runId"],
        "planDigest": config["planDigest"],
        "authorizationDigest": config["authorizationDigest"],
        "transportMode": "SELF_HOSTED_WINDOWS_HARNESS",
        "queryMarker": config["marker"],
        "networkInterface": config["networkInterface"],
        "sourceAddress": config["targetAddress"],
        "listenerAddress": config["listenerAddress"],
        "nameResolutionProtocol": config["nameResolutionProtocol"],
        "protocol": "HTTP",
        "markerQueryObserved": False,
        "responseSent": False,
        "responseCount": 0,
        "listenerOperational": False,
        "connectionObserved": False,
        "connectionCount": 0,
        "payloadBytes": 0,
        "authenticationChallengeIssued": False,
        "authenticationAttemptObserved": False,
        "messageTypesObserved": [],
        "testIdentityMatched": False,
        "sufficientObservationWindow": False,
        "ntlmOutboundBlocked": False,
        "clientSigningRequired": False,
        "protocolParserVerified": False,
        "credentialMaterialRetained": False,
        "credentialMaterialWrittenToDisk": False,
        "credentialMaterialIncludedInReport": False,
        "relayAttempted": False,
        "crackingAttempted": False,
        "firewallRuleCreated": False,
        "firewallRuleRemoved": False,
        "cleanupCompleted": False,
        "triggerProcessStarted": False,
        "scopeMismatchCount": 0,
        "sourceEndpointHash": None,
    }


def _error_observation(data: dict[str, Any]) -> dict[str, Any]:
    """Return a generic attested failure without exception details."""

    firewall_created = _firewall_state_has_created(
        data.get("firewallStatePath", "")
    )
    cleanup_completed = cleanup_firewall_state(
        data.get("firewallStatePath", "")
    )
    return {
        "runId": data.get("runId"),
        "planDigest": data.get("planDigest"),
        "authorizationDigest": data.get("authorizationDigest"),
        "transportMode": "SELF_HOSTED_WINDOWS_HARNESS",
        "queryMarker": data.get("marker"),
        "networkInterface": data.get("networkInterface"),
        "sourceAddress": data.get("targetAddress"),
        "listenerAddress": data.get("listenerAddress"),
        "nameResolutionProtocol": data.get("nameResolutionProtocol"),
        "protocol": "HTTP",
        "markerQueryObserved": False,
        "responseSent": False,
        "responseCount": 0,
        "listenerOperational": False,
        "connectionObserved": False,
        "connectionCount": 0,
        "payloadBytes": 0,
        "authenticationChallengeIssued": False,
        "authenticationAttemptObserved": False,
        "messageTypesObserved": [],
        "testIdentityMatched": False,
        "sufficientObservationWindow": False,
        "ntlmOutboundBlocked": False,
        "clientSigningRequired": False,
        "protocolParserVerified": False,
        "credentialMaterialRetained": False,
        "credentialMaterialWrittenToDisk": False,
        "credentialMaterialIncludedInReport": False,
        "relayAttempted": False,
        "crackingAttempted": False,
        "firewallRuleCreated": firewall_created,
        "firewallRuleRemoved": firewall_created and cleanup_completed,
        "cleanupCompleted": cleanup_completed,
        "triggerProcessStarted": False,
        "scopeMismatchCount": 0,
        "sourceEndpointHash": None,
        "errorCode": "LIVE_TRANSPORT_FAILED",
    }


def _firewall_state_has_created(state_path: object) -> bool:
    """Return whether recovery state records any created firewall rule."""

    try:
        state = load_strict_json(Path(str(state_path)))
    except (OSError, TypeError, ValueError):
        return False
    rules = state.get("rules", [])
    return (
        isinstance(rules, list)
        and any(
            isinstance(rule, dict) and rule.get("created") is True
            for rule in rules
        )
    )


def _write_firewall_state(
    path: Path,
    run_id: str,
    rules: list[dict[str, Any]],
) -> None:
    """Atomically persist only cleanup-safe firewall metadata."""

    document = {
        "schemaVersion": "1.0",
        "runId": run_id,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "rules": rules,
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(path)


def _attestation_key() -> bytes:
    """Read the parent-only ephemeral HMAC key from the child environment."""

    value = os.environ.pop("CSA_HARNESS_ATTESTATION_KEY", "")
    try:
        key = bytes.fromhex(value)
    except ValueError as error:
        raise RuntimeError("Harness attestation key is invalid") from error
    if len(key) != 32:
        raise RuntimeError("Harness attestation key is unavailable")
    return key


def _child_environment() -> dict[str, str]:
    """Return a child environment without the harness attestation key."""

    return {
        key: value
        for key, value in os.environ.items()
        if key != "CSA_HARNESS_ATTESTATION_KEY"
    }


if __name__ == "__main__":
    main()
