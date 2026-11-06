"""Inspect interrupted issuer operations while Lab is closed; preserve consumed grants."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from csa_console.storage import AssessmentStorage
from csa_console.trusted_grants import TrustedGrantStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("storage", "assessment", "session"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    store = TrustedGrantStore(AssessmentStorage(args.storage))
    session = store.sessions.load_session(args.assessment, args.session)
    print(json.dumps(store.reconcile(session), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("CSA-TRUST-RECONCILIATION-FAILED. Preserve the ledger and review protected storage/audit before reissue.", file=sys.stderr)
        raise SystemExit(1)
