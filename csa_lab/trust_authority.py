"""Independently provisioned Windows authority; no browser/self-enrollment path."""
import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from csa_console.canonical import sha256_bytes
from csa_console.trust_evidence import VerifiedTrustEvidence


def known_folder(identifier):
    if os.name != "nt":
        raise ValueError("TRUST_ENROLLMENT_PENDING")
    buffer = ctypes.create_unicode_buffer(32768)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    if shell.SHGetFolderPathW(None, identifier, None, 0, buffer) != 0:
        raise ValueError("CSA-TRUST-INSTALLATION")
    return Path(buffer.value)


def require_protected_path(path):
    """Reject reparse/write/ownership substitutions before running the verifier."""
    if os.name != "nt":
        raise ValueError("TRUST_ENROLLMENT_PENDING")
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    api.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD] + [ctypes.POINTER(pointer)] * 5
    api.GetNamedSecurityInfoW.restype = wintypes.DWORD
    api.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wintypes.LPWSTR)]
    api.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel.GetFileAttributesW.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [pointer]
    trusted = {"S-1-5-18", "S-1-5-32-544"}
    roots = {known_folder(0x26), known_folder(0x23)}
    writes = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000

    def sid_text(sid):
        value = wintypes.LPWSTR()
        if not api.ConvertSidToStringSidW(sid, ctypes.byref(value)):
            raise ValueError("CSA-TRUST-POLICY-ACL")
        try:
            return value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, pointer))

    current = Path(os.path.abspath(path))
    reached_root = False
    while current != current.parent:
        attributes = kernel.GetFileAttributesW(str(current))
        if attributes == 0xFFFFFFFF or attributes & 0x400:
            raise ValueError("CSA-TRUST-POLICY-PATH")
        if current in roots:
            reached_root = True
            break
        owner, group, dacl, sacl, descriptor = (pointer() for _ in range(5))
        error = api.GetNamedSecurityInfoW(str(current), 1, 1 | 4, ctypes.byref(owner), ctypes.byref(group),
            ctypes.byref(dacl), ctypes.byref(sacl), ctypes.byref(descriptor))
        if error:
            raise ValueError("CSA-TRUST-POLICY-ACL")
        try:
            if not dacl.value or sid_text(owner) not in trusted:
                raise ValueError("CSA-TRUST-POLICY-ACL")
            count = ctypes.c_ushort.from_address(dacl.value + 4).value
            for index in range(count):
                ace = pointer()
                if not api.GetAce(dacl, index, ctypes.byref(ace)):
                    raise ValueError("CSA-TRUST-POLICY-ACL")
                kind = ctypes.c_ubyte.from_address(ace.value).value
                flags = ctypes.c_ubyte.from_address(ace.value + 1).value
                if kind in {1, 6, 10, 12} or flags & 8:  # Deny or inherit-only.
                    continue
                if kind not in {0, 5, 9, 11}:
                    raise ValueError("CSA-TRUST-POLICY-ACL")
                mask = ctypes.c_uint32.from_address(ace.value + 4).value
                offset = 8
                if kind in {5, 11}:
                    object_flags = ctypes.c_uint32.from_address(ace.value + 8).value
                    offset = 12 + (16 if object_flags & 1 else 0) + (16 if object_flags & 2 else 0)
                if mask & writes and sid_text(pointer(ace.value + offset)) not in trusted:
                    raise ValueError("CSA-TRUST-POLICY-ACL")
        finally:
            kernel.LocalFree(descriptor)
        current = current.parent
    if not reached_root:
        raise ValueError("CSA-TRUST-INSTALLATION")


class NativeTrustAuthority:
    """Only an OS-authenticated, protected installed verifier can produce REAL."""
    assurance = "REAL"

    def __init__(self, policy_path, approval_path):
        self.policy_path, self.approval_path = Path(policy_path), Path(approval_path)

    @classmethod
    def for_recipient(cls, recipient):
        import re
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", recipient):
            raise ValueError("CSA-TRUST-RECIPIENT")
        root = known_folder(0x23) / "CSA/Trust/recipients" / recipient
        return cls(root / "policy.json", root / "distribution-approval.json")

    def verify(self, bundle):
        try:
            return self._verify(bundle)
        except (subprocess.TimeoutExpired, AttributeError, TypeError) as error:
            raise ValueError("CSA-TRUST-INSPECTION-FAILED") from error

    def _verify(self, bundle):
        executable = known_folder(0x26) / "CSA/Collector/CSA-TrustedCollector.exe"
        for path in (self.policy_path, self.approval_path, executable):
            require_protected_path(path)
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        # Authenticate the native verifier before executing it, using the
        # independent protected policy, not data supplied by this bundle.
        quoted = str(executable).replace("'", "''")
        command = "$s=Get-AuthenticodeSignature -LiteralPath '" + quoted + "'; if ([string]$s.Status -ne 'Valid' -or $null -eq $s.TimeStamperCertificate) {exit 1}; [Convert]::ToBase64String($s.SignerCertificate.RawData)"
        powershell = known_folder(0x24) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, text=True, timeout=45)
        if result.returncode:
            raise ValueError("CSA-TRUST-AUTHENTICODE")
        certificate = x509.load_der_x509_certificate(base64.b64decode(result.stdout.strip(), validate=True))
        public = certificate.public_key()
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 3072:
            raise ValueError("CSA-TRUST-PUBLISHER")
        certificate_digest = sha256_bytes(certificate.public_bytes(serialization.Encoding.DER))
        spki = sha256_bytes(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        now = time.time()
        matching = [key for key in policy.get("publishers", []) if key.get("certificateSha256") == certificate_digest
                    and key.get("spkiSha256") == spki and key.get("revoked") is False
                    and key.get("issuedAt", now + 121) <= now + 120 and key.get("expiresAt", 0) > now]
        if len(matching) != 1:
            raise ValueError("CSA-TRUST-PUBLISHER")
        result = subprocess.run([str(executable), "--inspect-bundle", str(Path(bundle).resolve()),
            "--policy", str(self.policy_path), "--approval", str(self.approval_path)], capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise ValueError("TRUST_ENROLLMENT_PENDING")
        record = json.loads(result.stdout)
        if set(record) != {"assurance", "facts"} or record["assurance"] != "REAL":
            raise ValueError("CSA-TRUST-ASSURANCE")
        return VerifiedTrustEvidence("REAL", record["facts"])
