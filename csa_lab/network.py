"""Windows network discovery and conservative interface selection."""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from typing import Any

from csa_lab.models import NetworkInterface

VIRTUAL_HINTS = (
    "hyper-v",
    "vmware",
    "virtualbox",
    "vethernet",
    "loopback",
    "wsl",
)
VPN_HINTS = ("vpn", "wireguard", "openvpn", "tailscale", "zerotier")


def discover_network_interfaces() -> list[NetworkInterface]:
    """Return usable Windows IPv4 interfaces in deterministic preference order."""

    values = _powershell_interfaces()
    if not values:
        values = _socket_fallback()
    interfaces = [_to_interface(item) for item in values]
    usable = [
        item
        for item in interfaces
        if item.connected and _is_usable_address(item.address)
    ]
    physical_private = [
        item
        for item in usable
        if not item.is_virtual
        and not item.is_vpn
        and item.profile.casefold() != "public"
    ]
    preferred_ids = {
        item.interface_id for item in physical_private
    } or {
        item.interface_id
        for item in usable
        if not item.is_virtual and not item.is_vpn
    }
    for item in usable:
        item.recommended = item.interface_id in preferred_ids
        warnings = []
        if item.profile.casefold() == "public":
            warnings.append("Public network profile")
        if item.is_vpn:
            warnings.append("VPN interface")
        if item.is_virtual and physical_private:
            warnings.append("Virtual interface")
        item.warning = "; ".join(warnings)
    return sorted(
        usable,
        key=lambda item: (
            not item.recommended,
            item.profile.casefold() == "public",
            item.is_vpn,
            item.is_virtual,
            item.name.casefold(),
            item.address,
        ),
    )


def select_default_interface(
    interfaces: list[NetworkInterface],
) -> NetworkInterface:
    """Select the safest discovered interface or fail with an actionable error."""

    if not interfaces:
        raise ValueError("No connected collection network was found")
    return sorted(
        interfaces,
        key=lambda item: (
            not item.recommended,
            item.profile.casefold() == "public",
            item.is_vpn,
            item.is_virtual,
            item.name.casefold(),
        ),
    )[0]


def _powershell_interfaces() -> list[dict[str, Any]]:
    script = (
        "$ErrorActionPreference='Stop';"
        "Get-NetIPConfiguration | ForEach-Object {"
        "$p=Get-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex "
        "-ErrorAction SilentlyContinue | Select-Object -First 1;"
        "foreach($v4 in @($_.IPv4Address)){"
        "[pscustomobject]@{"
        "InterfaceId=[string]$_.InterfaceIndex;"
        "Name=[string]$_.InterfaceAlias;"
        "Address=[string]$v4.IPAddress;"
        "PrefixLength=[int]$v4.PrefixLength;"
        "Profile=if($p){[string]$p.NetworkCategory}else{'Unknown'};"
        "Description=[string]$_.InterfaceDescription;"
        "Status=if($_.NetAdapter){[string]$_.NetAdapter.Status}else{'Unknown'}"
        "}}} | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = completed.stdout.strip()
        if not raw:
            return []
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else [parsed]
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def _socket_fallback() -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    try:
        addresses = socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET
        )
    except OSError:
        return values
    for index, value in enumerate(
        sorted({item[4][0] for item in addresses}), start=1
    ):
        values.append(
            {
                "InterfaceId": f"fallback-{index}",
                "Name": "Windows network",
                "Address": value,
                "PrefixLength": 24,
                "Profile": "Unknown",
                "Description": "",
                "Status": "Up",
            }
        )
    return values


def _to_interface(value: dict[str, Any]) -> NetworkInterface:
    address = str(value.get("Address", ""))
    prefix = int(value.get("PrefixLength", 24))
    try:
        subnet = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    except ValueError:
        subnet = ""
    combined = " ".join(
        (
            str(value.get("Name", "")),
            str(value.get("Description", "")),
        )
    ).casefold()
    return NetworkInterface(
        interface_id=str(value.get("InterfaceId", address)),
        name=str(value.get("Name", "Network")),
        address=address,
        subnet=subnet,
        profile=str(value.get("Profile", "Unknown")),
        adapter_type=str(value.get("Description", "")),
        connected=str(value.get("Status", "")).casefold() in {
            "up",
            "connected",
            "unknown",
        },
        is_virtual=any(item in combined for item in VIRTUAL_HINTS),
        is_vpn=any(item in combined for item in VPN_HINTS),
    )


def _is_usable_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.version == 4
        and not address.is_loopback
        and not address.is_unspecified
        and not address.is_link_local
    )

