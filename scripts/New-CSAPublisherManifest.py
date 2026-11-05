"""Author publisher release metadata on the controlled signing host only."""
import argparse
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from csa_console.file_security import restrict_directory
from csa_lab.trusted_distribution import publisher_manifest, sign_with_windows_store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "bootstrap", "entry-point", "output", "key-id", "version", "commit",
                 "certificate-thumbprint", "publisher-certificate-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--release-sequence", type=int, required=True)
    parser.add_argument("--valid-hours", type=int, default=24)
    args = parser.parse_args()
    if args.release_sequence < 1 or not 0 < args.valid_hours <= 24 * 30:
        raise ValueError("CSA-TRUST-SCOPE")
    output = Path(args.output)
    if output.exists():
        raise ValueError("CSA-TRUST-OUTPUT")
    output.mkdir(parents=True)
    restrict_directory(output)
    now = int(time.time())
    bootstrap, entry = Path(args.bootstrap), Path(args.entry_point)
    content = publisher_manifest(Path(args.package), bootstrap, entry, key_id=args.key_id,
        version=args.version, commit=args.commit, release_sequence=args.release_sequence,
        issued_at=now, expires_at=now + args.valid_hours * 3600)
    signature = sign_with_windows_store(content, args.certificate_thumbprint, output,
        publisher_certificate_sha256=args.publisher_certificate_sha256, publisher_artifacts=(bootstrap, entry))
    (output / "publisher-manifest.json").write_bytes(content)
    (output / "publisher-manifest.p7s").write_bytes(signature)
    print("CSA-PUBLISHER-MANIFEST-SIGNED. Preserve with the exact final immutable artifacts.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("CSA-PUBLISHER-MANIFEST-FAILED. Final signatures and the approved publisher identity are required.", file=sys.stderr)
        raise SystemExit(1)
