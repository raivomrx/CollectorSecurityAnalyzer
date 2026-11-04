"""Recognize only evidenced OS families and architecture aliases for CVE applicability."""

from __future__ import annotations

import re
from typing import Any

OS_KEYS = ("OS", "OSName", "OperatingSystem", "Operating System", "operatingSystem.name")
ARCH_KEYS = ("Architecture", "OSArchitecture", "SystemType", "TargetHW", "MachineArchitecture", "operatingSystem.architecture")


def read_environment(data: dict[str, Any] | None, keys: tuple[str, ...]) -> str | None:
    if not isinstance(data, dict):
        return None
    indexed = {str(key).casefold(): value for key, value in data.items()}
    for key in keys:
        value = indexed.get(key.casefold())
        if value is None and "." in key:
            parent, child = key.casefold().split(".", 1)
            obj = indexed.get(parent)
            if isinstance(obj, dict):
                value = next((v for k, v in obj.items() if str(k).casefold() == child), None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def environment_key(value: str) -> str:
    return " ".join(re.sub(r"[_-]", " ", value.casefold()).split())


def os_identity(value: str | None) -> tuple[str, str | None] | None:
    text = environment_key(value or "")
    if text == "windows":
        return "windows", None
    windows = re.fullmatch(r"(?:microsoft )?windows (11|10|8\.1|8|7|vista|xp|server(?: 20[0-9]{2})?)(?: .+)?", text)
    if windows:
        return "windows", windows[1]
    if re.fullmatch(r"(?:gnu/linux|linux|linux kernel|ubuntu(?: linux)?|debian(?: linux)?|red hat enterprise linux|fedora|suse linux)(?: [0-9][a-z0-9. ]*)?", text):
        return "linux", None
    if re.fullmatch(r"(?:apple )?(?:macos|mac os x|os x)(?: [a-z0-9. ]+)?", text):
        return "macos", None
    if text in {"android", "ios", "freebsd"}:
        return text, None
    return None


def platform_matches(criteria: str, observed: str | None, *, exact_product: bool = False) -> bool | None:
    expected = os_identity(criteria)
    actual = os_identity(observed)
    if expected is None or actual is None:
        return None
    if expected[0] != actual[0]:
        return False
    if expected[1] is None:
        # A kernel/distribution constraint needs more than a Linux family match.
        if exact_product and expected[0] == "linux" and environment_key(criteria) not in {"linux", "gnu/linux", environment_key(observed or "")}:
            return None
        return True
    if actual[1] is None or (expected[1] == "server" and actual[1].startswith("server")):
        return None if actual[1] is None else True
    if expected[1].startswith("server ") and actual[1] == "server":
        return None
    if expected[1] != actual[1]:
        return False
    expected_name = environment_key(criteria).removeprefix("microsoft ")
    return True if expected_name == f"windows {expected[1]}" or expected_name == environment_key(observed or "").removeprefix("microsoft ") else None


def architecture_identity(value: str | None) -> str | None:
    return {
        "amd64": "x64", "x64": "x64", "x86 64": "x64", "x64 based pc": "x64",
        "x86": "x86", "i386": "x86", "i686": "x86", "win32": "x86", "x86 based pc": "x86",
        "arm64": "arm64", "aarch64": "arm64", "arm64 based pc": "arm64",
        "arm": "arm", "arm32": "arm", "armv7": "arm",
    }.get(environment_key(value or ""))
