"""Least-privilege temporary Windows Firewall lifecycle."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol

from csa_lab.models import FirewallRuleSpec


class FirewallManager(Protocol):
    """Define the firewall operations used by the Lab service."""

    def create(self, spec: FirewallRuleSpec) -> None:
        """Create one assessment-scoped inbound rule."""

    def remove(self, rule_name: str) -> None:
        """Remove one assessment-scoped rule."""

    def exists(self, rule_name: str) -> bool:
        """Return whether the rule currently exists."""


class NullFirewallManager:
    """In-memory firewall adapter for tests and explicit disabled mode."""

    def __init__(self) -> None:
        self.rules: dict[str, FirewallRuleSpec] = {}

    def create(self, spec: FirewallRuleSpec) -> None:
        """Record a rule without changing the host firewall."""

        self.rules[spec.rule_name] = spec

    def remove(self, rule_name: str) -> None:
        """Remove a recorded rule."""

        self.rules.pop(rule_name, None)

    def exists(self, rule_name: str) -> bool:
        """Return whether a rule is recorded."""

        return rule_name in self.rules


class WindowsFirewallManager:
    """Manage exact Windows Firewall rules through one bounded UAC action."""

    RULE_PREFIX = "CSA Lab Temporary "

    def create(self, spec: FirewallRuleSpec) -> None:
        """Create an exact program, address, port, profile and subnet rule."""

        validate_firewall_spec(spec)
        arguments = [
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={spec.rule_name}",
            "dir=in",
            "action=allow",
            f"program={spec.program_path}",
            f"protocol={spec.protocol}",
            f"localip={spec.local_address}",
            f"localport={spec.local_port}",
            f"remoteip={spec.remote_subnet}",
            f"profile={spec.profile}",
            "enable=yes",
        ]
        self._elevated_netsh(arguments)
        if not self.exists(spec.rule_name):
            raise OSError("CSA-NET-003: temporary firewall rule was not created")

    def remove(self, rule_name: str) -> None:
        """Remove only the named CSA temporary rule."""

        _validate_rule_name(rule_name)
        if not self.exists(rule_name):
            return
        self._elevated_netsh(
            [
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={rule_name}",
            ]
        )
        if self.exists(rule_name):
            raise OSError("CSA-NET-004: temporary firewall rule was not removed")

    def exists(self, rule_name: str) -> bool:
        """Query an exact rule name without elevation."""

        _validate_rule_name(rule_name)
        completed = subprocess.run(
            [
                "netsh.exe",
                "advfirewall",
                "firewall",
                "show",
                "rule",
                f"name={rule_name}",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return completed.returncode == 0 and rule_name.casefold() in (
            completed.stdout.casefold()
        )

    def _elevated_netsh(self, arguments: list[str]) -> None:
        """Run one allowlisted netsh action through Windows UAC."""

        payload = {
            "executable": str(
                Path(os.environ.get("SystemRoot", r"C:\Windows"))
                / "System32"
                / "netsh.exe"
            ),
            "arguments": arguments,
        }
        with tempfile.TemporaryDirectory(prefix="CSA-Firewall-") as directory:
            request = Path(directory) / "request.json"
            result = Path(directory) / "result.json"
            request.write_text(json.dumps(payload), encoding="utf-8")
            helper = Path(__file__).resolve().parent / "powershell" / (
                "Invoke-CSAFirewallAction.ps1"
            )
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(helper),
                    "-RequestPath",
                    str(request),
                    "-ResultPath",
                    str(result),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if completed.returncode != 0 or not result.exists():
                raise PermissionError(
                    "CSA-NET-002: firewall access was not approved"
                )
            outcome = json.loads(result.read_text(encoding="utf-8-sig"))
            exit_code = int(outcome.get("exitCode", -1))
            if exit_code != 0:
                raise OSError(
                    "CSA-NET-003: Windows rejected the firewall rule "
                    f"(netsh exit code {exit_code})"
                )


def validate_firewall_spec(spec: FirewallRuleSpec) -> None:
    """Reject any broad or incomplete firewall rule specification."""

    _validate_rule_name(spec.rule_name)
    program = Path(spec.program_path)
    if not program.is_absolute():
        raise ValueError("Firewall program path must be absolute")
    if spec.protocol != "TCP":
        raise ValueError("CSA collection firewall rule must use TCP")
    if not 1 <= spec.local_port <= 65535:
        raise ValueError("Firewall port is outside the valid range")
    if spec.local_address in {"", "*", "Any", "0.0.0.0"}:
        raise ValueError("Firewall rule requires a concrete local address")
    if spec.remote_subnet in {"", "*", "Any", "0.0.0.0/0"}:
        raise ValueError("Firewall rule requires a bounded source subnet")
    if spec.profile.casefold() not in {"private", "domain"}:
        raise ValueError(
            "The selected Windows network profile is Public. Change this "
            "trusted lab network to Private in Windows Settings, or select "
            "another Private or Domain network, then create a new assessment."
        )


def _validate_rule_name(rule_name: str) -> None:
    if not rule_name.startswith(WindowsFirewallManager.RULE_PREFIX):
        raise ValueError("Firewall rule name is outside the CSA namespace")
    if len(rule_name) > 160 or any(char in rule_name for char in "\r\n\""):
        raise ValueError("Firewall rule name is unsafe")
