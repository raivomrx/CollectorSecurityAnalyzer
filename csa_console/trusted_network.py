"""ADR 565 authenticated invitation/challenge/download service, gated independently."""
import base64
import ipaddress
import json
from pathlib import Path
import threading
import time

from csa_console.canonical import sha256_bytes
from csa_console.distribution import DistributionDenied
from csa_console.enums import SessionStatus
from csa_console.network import source_is_allowed
from csa_console.sessions import AssessmentSessionService
from csa_console.trusted_grants import TrustedGrantStore
from csa_console.trust_evidence import VerifiedTrustEvidence


class TrustedNetworkService:
    def __init__(self, storage, assessment_id, session_id, *, authority_factory=None, isolated_testing=False):
        self.storage, self.assessment_id, self.session_id = storage, assessment_id, session_id
        self.sessions = AssessmentSessionService(storage)
        self.grants = TrustedGrantStore(storage)
        if authority_factory is None:
            from csa_lab.trust_authority import NativeTrustAuthority
            authority_factory = NativeTrustAuthority.for_recipient
        self.authority_factory = authority_factory
        self.isolated_testing = isolated_testing
        self._cache, self._lock = {}, threading.RLock()

    def _session(self, source):
        session = self.sessions.load_session(self.assessment_id, self.session_id)
        from csa_console.sessions import _parse_utc
        if (session.status != SessionStatus.OPEN or _parse_utc(session.expires_at).timestamp() <= time.time()
                or not source_is_allowed(session, source)):
            raise DistributionDenied()
        return session

    @staticmethod
    def _read(path, maximum):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise ValueError("CSA-TRUST-PATH")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("CSA-TRUST-SIZE")
        return data

    def _view(self, envelope_id, source):
        session = self._session(source)
        row = self.grants.record(session, envelope_id)
        if not row["networkEnabled"] or row["used"] or not row["bundlePath"]:
            raise DistributionDenied()
        bundle = Path(row["bundlePath"])
        # Reauthenticate independent local authority; neither DB claims nor a
        # browser can promote simulated enrollment to REAL.
        with self._lock:
            cached = self._cache.get(envelope_id)
            if cached is None or cached[0] <= time.time():
                authority = self.authority_factory(row["recipientId"])
                proof = authority.verify(bundle)
                if not isinstance(proof, VerifiedTrustEvidence):
                    raise DistributionDenied()
                if proof.assurance == "REAL" and proof.facts["approvalState"] not in {"PILOT_APPROVED", "RELEASE_APPROVED"}:
                    raise DistributionDenied()
                expiry = min(time.time() + 15, proof.facts["expiresAt"])
                self._cache[envelope_id] = (expiry, proof)
            else:
                proof = cached[1]
        if proof.assurance == "TEST_ONLY" and not (
            self.isolated_testing and ipaddress.ip_address(session.listen_address).is_loopback):
            raise DistributionDenied()
        if json.loads(row["provenance"] or "{}") != proof.record():
            raise ValueError("CSA-TRUST-ATTESTATION-SCOPE")
        if proof.facts["expiresAt"] <= time.time() or proof.facts["envelopeId"] != envelope_id:
            raise DistributionDenied()
        details = json.loads(row["details"])
        for key, expected in {**details, "envelopeId": envelope_id, "recipientId": row["recipientId"],
                              "collectorBuildDigest": row["buildDigest"]}.items():
            if key in proof.facts and proof.facts[key] != expected:
                raise ValueError("CSA-TRUST-ATTESTATION-SCOPE")
        files = {name: self._read(bundle / name, maximum) for name, maximum in {
            "publisher-manifest.json": 2 * 1024 * 1024, "publisher-manifest.p7s": 65536,
            "session-envelope.json": 1024 * 1024, "session-envelope.p7s": 65536}.items()}
        for name, key in {"publisher-manifest.json": "publisherManifestDigest", "publisher-manifest.p7s": "publisherSignatureDigest",
                          "session-envelope.json": "sessionEnvelopeDigest", "session-envelope.p7s": "sessionSignatureDigest"}.items():
            if sha256_bytes(files[name]) != proof.facts.get(key):
                raise ValueError("CSA-TRUST-SIGNATURE")
        return session, row, bundle, proof, files

    def advertisements(self, source):
        session = self._session(source)
        result = []
        for row in self.grants.network_records(session):
            try:
                _, _, _, proof, _ = self._view(row["envelopeId"], source)
            except (OSError, ValueError, KeyError):
                continue
            result.append({"labId": proof.facts["labId"], "envelopeId": row["envelopeId"],
                "recipientId": row["recipientId"], "expiresAt": row["expiresAt"], "publisherKeyId": proof.facts["publisherKeyId"],
                "publisherCertificateSha256": proof.facts["publisherCertificateSha256"], "origin": proof.facts["origin"],
                "approvalState": proof.facts["approvalState"],
                "copyState": "APPROVED" if proof.assurance == "REAL" else "TEST_ONLY", "assurance": proof.assurance})
        return result

    def metadata(self, envelope_id, source):
        _, _, _, _, files = self._view(envelope_id, source)
        return {key: base64.b64encode(files[name]).decode("ascii") for key, name in {
            "publisherManifest": "publisher-manifest.json", "publisherSignature": "publisher-manifest.p7s",
            "sessionEnvelope": "session-envelope.json", "sessionSignature": "session-envelope.p7s"}.items()}

    def challenge(self, envelope_id, source):
        session, _, _, _, files = self._view(envelope_id, source)
        return self.grants.challenge(session, envelope_id, sha256_bytes(files["session-envelope.json"]))

    def authorize(self, envelope_id, source, body, secret):
        session, _, _, _, files = self._view(envelope_id, source)
        if set(body) != {"challengeId", "nonce", "recipientId", "envelopeDigest", "requestedMode"} or body["envelopeDigest"] != sha256_bytes(files["session-envelope.json"]):
            raise ValueError("CSA-TRUST-CHALLENGE")
        return self.grants.authorize(session, envelope_id, body["challengeId"], body["nonce"], body["recipientId"], secret, body["requestedMode"])

    def download_grant(self, envelope_id, source, ticket):
        session, _, _, _, _ = self._view(envelope_id, source)
        return self.grants.mint_download(session, envelope_id, ticket)

    def package(self, envelope_id, source, grant):
        session, row, bundle, proof, _ = self._view(envelope_id, source)
        data = self._read(bundle / "collector.zip", 64 * 1024 * 1024)
        if sha256_bytes(data) != proof.facts["packageDigest"]:
            raise ValueError("CSA-TRUST-DIGEST")
        self.grants.consume_download(session, envelope_id, grant)
        return data
