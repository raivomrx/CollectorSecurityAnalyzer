"""Build and inspect assessment-bound single-file Collector executables."""

from __future__ import annotations

import hashlib
import hmac
import io
import shutil
import struct
import zipfile
from pathlib import Path

MAGIC = b"CSA51PKG"
TRAILER_SIZE = 8 + 32 + len(MAGIC)


def build_bound_collector(
    bootstrap_executable: str | Path,
    package_directory: str | Path,
    output_path: str | Path,
) -> Path:
    """Append a deterministic verified package to the stable Collector stub."""

    bootstrap = Path(bootstrap_executable).resolve()
    package = Path(package_directory).resolve()
    output = Path(output_path).resolve()
    if not bootstrap.is_file():
        raise FileNotFoundError("CSA Collector bootstrap executable is unavailable")
    if _signed_pe(bootstrap.read_bytes()):
        raise ValueError("CSA-TRUST-IMMUTABLE: Signed publisher executables cannot receive a session overlay")
    if not (package / "trusted-manifest.json").is_file():
        raise ValueError("Collector package trusted manifest is unavailable")
    payload = _package_zip(package)
    digest = hashlib.sha256(payload).digest()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with bootstrap.open("rb") as source, temporary.open("wb") as destination:
        shutil.copyfileobj(source, destination)
        destination.write(payload)
        destination.write(struct.pack("<Q", len(payload)))
        destination.write(digest)
        destination.write(MAGIC)
    temporary.replace(output)
    return output


def _signed_pe(value: bytes) -> bool:
    """Recognize a PE certificate directory without executing the artifact."""
    if len(value) < 64 or value[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", value, 60)[0]
    if offset + 26 > len(value) or value[offset:offset + 4] != b"PE\x00\x00":
        return False
    optional = offset + 24
    magic = struct.unpack_from("<H", value, optional)[0]
    certificate = optional + (128 if magic == 0x10B else 144 if magic == 0x20B else len(value))
    return certificate + 8 <= len(value) and any(struct.unpack_from("<II", value, certificate))


def read_bound_collector_payload(path: str | Path) -> bytes:
    """Return and verify the appended Collector package bytes."""

    value = Path(path)
    with value.open("rb") as handle:
        handle.seek(-TRAILER_SIZE, io.SEEK_END)
        trailer = handle.read(TRAILER_SIZE)
        length = struct.unpack("<Q", trailer[:8])[0]
        expected = trailer[8:40]
        if trailer[40:] != MAGIC:
            raise ValueError("Collector executable package marker is invalid")
        payload_start = value.stat().st_size - TRAILER_SIZE - length
        if payload_start <= 0:
            raise ValueError("Collector executable package length is invalid")
        handle.seek(payload_start)
        payload = handle.read(length)
    if not hmac.compare_digest(hashlib.sha256(payload).digest(), expected):
        raise ValueError("Collector executable package digest is invalid")
    return payload


def build_script_collector(package_directory: str | Path, output_path: str | Path) -> Path:
    """Archive the same verified session package used by the executable."""

    from csa_console.collector_package import verify_collector_package

    package = Path(package_directory).resolve()
    verify_collector_package(package)
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_bytes(_package_zip(package))
    temporary.replace(output)
    return output


def _package_zip(root: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in sorted(
            (item for item in root.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(root).as_posix(),
        ):
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, path.read_bytes())
    return buffer.getvalue()
