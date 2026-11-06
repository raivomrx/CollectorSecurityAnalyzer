"""Issue one independently signed handoff using an enrolled Windows Lab key."""
import argparse
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from csa_console.storage import AssessmentStorage
from csa_console.trusted_grants import TrustedGrantStore
from csa_lab.trusted_distribution import create_trusted_bundle, sign_with_windows_store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("storage", "assessment", "session", "package", "publisher-release", "output",
                 "lab-id", "lab-key-id", "lab-certificate-thumbprint", "recipient-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--network", action="store_true", help="Require independently approved enrollment and issue a v2 network invitation.")
    parser.add_argument("--verify-local-provenance", action="store_true", help="Verify approved production provenance for a private v1 handoff.")
    args = parser.parse_args()
    store = TrustedGrantStore(AssessmentStorage(Path(args.storage)))
    session = store.sessions.load_session(args.assessment, args.session)
    publisher = Path(args.publisher_release)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    authority = None
    if args.network or args.verify_local_provenance:
        from csa_lab.trust_authority import NativeTrustAuthority
        authority = NativeTrustAuthority.for_recipient(args.recipient_id)
    create_trusted_bundle(output, Path(args.package), (publisher / "publisher-manifest.json").read_bytes(),
        (publisher / "publisher-manifest.p7s").read_bytes(), grant_store=store, session=session,
        sign_session=lambda data: sign_with_windows_store(data, args.lab_certificate_thumbprint, output.parent),
        key_id=args.lab_key_id, lab_id=args.lab_id, recipient_id=args.recipient_id,
        envelope_id=secrets.token_urlsafe(24), nonce=secrets.token_urlsafe(32), issued_at=int(time.time()),
        network=args.network, authority=authority)
    print("CSA-TRUST-BUNDLE-ISSUED. Deliver through the independently approved handoff channel.")
    if args.network:
        print("Deliver assessor-authorization.txt privately to the authorized recipient. Never publish it or paste it into a command.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("CSA-TRUST-BUNDLE-FAILED. Check enrollment, signer availability and session scope.", file=sys.stderr)
        raise SystemExit(1)
