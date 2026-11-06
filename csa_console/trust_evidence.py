"""Verifier-produced server evidence. No HTTP/client declaration constructs it."""
from dataclasses import dataclass
import json
import re
from types import MappingProxyType

from csa_console.canonical import sha256_value


@dataclass(frozen=True)
class VerifiedTrustEvidence:
    assurance: str
    facts: object

    def __post_init__(self):
        if self.assurance not in {"REAL", "TEST_ONLY"}:
            raise ValueError("CSA-TRUST-ASSURANCE")
        hashes = {"publisherManifestDigest", "publisherSignatureDigest", "sessionEnvelopeDigest",
                  "sessionSignatureDigest", "sessionManifestDigest", "packageDigest", "collectorBuildDigest",
                  "profileDigest", "privacyPolicyDigest", "publisherSpkiSha256", "labSpkiSha256",
                  "publisherCertificateSha256", "tlsFingerprint", "policyDigest", "approvalDigest"}
        identifiers = {"assessmentId", "sessionId", "envelopeId", "recipientId", "labId", "publisherKeyId", "labKeyId"}
        states = {"TEST_ONLY"} if self.assurance == "TEST_ONLY" else {"PILOT_APPROVED", "RELEASE_APPROVED"}
        value = dict(self.facts)
        if (value.keys() != hashes | identifiers | {"expiresAt", "origin", "approvalState"}
                or any(not isinstance(value[key], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value[key]) for key in hashes)
                or any(not isinstance(value[key], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value[key]) for key in identifiers)
                or type(value["expiresAt"]) is not int or not isinstance(value["origin"], str)
                or not value["origin"].startswith("https://") or value["approvalState"] not in states):
            raise ValueError("CSA-TRUST-ATTESTATION-SCOPE")
        object.__setattr__(self, "facts", MappingProxyType(json.loads(json.dumps(value))))

    def record(self):
        return {"assurance": self.assurance, "facts": dict(self.facts)}

    @property
    def digest(self):
        return sha256_value(self.record())

    def bind(self, session, envelope):
        for key, expected in {"assessmentId": session.assessment_id, "sessionId": session.session_id,
                "envelopeId": envelope["envelopeId"], "recipientId": envelope["recipientId"],
                "packageDigest": envelope["packageDigest"], "publisherManifestDigest": envelope["publisherManifestDigest"],
                "sessionManifestDigest": envelope["sessionManifestDigest"], "labId": envelope["labId"],
                "profileDigest": envelope["profileDigest"], "privacyPolicyDigest": envelope["privacyPolicyDigest"],
                "tlsFingerprint": envelope["tlsFingerprint"], "origin": envelope["origin"]}.items():
            if self.facts.get(key) != expected:
                raise ValueError("CSA-TRUST-ATTESTATION-SCOPE")
        if not 0 < self.facts["expiresAt"] <= envelope["expiresAt"]:
            raise ValueError("CSA-TRUST-ATTESTATION-SCOPE")
