"""Current-Windows-user DPAPI storage for the optional NVD API credential."""

from __future__ import annotations

import ctypes
import os
import re
from pathlib import Path
from ctypes import wintypes


class _Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt(data: bytes, *, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Secure NVD key storage requires Windows DPAPI")
    buffer = ctypes.create_string_buffer(data)
    incoming = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    outgoing = _Blob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    function.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    function.restype = wintypes.BOOL
    # CRYPTPROTECT_UI_FORBIDDEN; no LOCAL_MACHINE flag: bound to this user.
    if not function(ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(outgoing)):
        raise RuntimeError("Windows could not access the protected NVD key")
    try:
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        kernel32.LocalFree(outgoing.data)


class NvdSecretStore:
    """Store only encrypted bytes, outside assessment/export directories."""

    def __init__(self, application_root: Path) -> None:
        self.path = application_root / "config" / "nvd-api-key.dpapi"

    def status(self) -> dict:
        saved = self.path.is_file()
        environment = bool(os.getenv("NVD_API_KEY"))
        return {"configured": saved or environment, "savedKey": saved,
                "source": "Windows user store" if saved else "Environment variable" if environment else "Not configured"}

    def load(self) -> str | None:
        if self.path.is_file():
            try:
                return _crypt(self.path.read_bytes(), decrypt=True).decode("utf-8")
            except Exception:
                raise RuntimeError("Saved NVD key cannot be opened by this Windows user; replace or remove it") from None
        return None  # NvdClient retains the existing environment-variable path.

    def save(self, key: str) -> None:
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9-]{16,128}", key):
            raise ValueError("Enter a valid NVD API key without spaces")
        encrypted = _crypt(key.encode("utf-8"), decrypt=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        try:
            temporary.write_bytes(encrypted)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def remove(self) -> None:
        self.path.unlink(missing_ok=True)
