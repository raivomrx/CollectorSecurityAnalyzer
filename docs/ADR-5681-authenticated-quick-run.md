# ADR 5681 — approved ADR 565 implementation and Quick Run amendment

Status: development authorized by the project lead/Architect correction package
and explicit Architecture Decision Update, 2026-11-05. Production enrollment and
release acceptance remain PENDING / HOLD. This implements ADR 565's two existing
authorities and one-use assessor authorization; it introduces no new trust root,
publisher delegation, cryptographic algorithm or device-attestation claim.

The project lead's newer instruction supersedes the correction attachment's
execution-policy prohibition: **Quick Run – ExecutionPolicy Bypass** is supported
for the Collector process only. It never changes persistent policy, bypasses
GPO, disables AMSI/Defender, or circumvents WDAC/AppLocker. Both normal and Quick
Run invoke the same independently installed immutable verifier and Collector.

## Public invitation and private authority

The v1 local bundle is private. Its nonce was also its private submission
capability, so it MUST NOT simply become a public network invitation.

The v2 signed Lab envelope keeps a public random invitation nonce. Its signed
submission policy adds `authorizationDigest`, the SHA-256 of a separate random
submission capability inside the private session config. The archive digest
binds that config. A public nonce/locator never authorizes download/submission.
Publisher manifest, RSA-3072+/SHA-256 detached CMS, canonical JSON, locally
enrolled independent publisher/Lab keys, exact TLS pin and engine checks remain
the approved ADR 565 mechanisms. v1 stays local-only; there is no downgrade.

1. Managed/assessor provisioning independently authenticates the immutable EXE /
   PS entry and protected local policy. The genuine command's origin must also
   be independently authenticated. The command contains only opaque Lab and
   invitation locators, never an enrollment/download credential or join code.
2. The installed verifier validates itself, policy freshness, publisher release
   and signed Lab invitation/recipient/scope/TLS before collecting evidence or
   asking for the assessor's one-time secret. This secret is delivered through
   the independently approved private channel and read without echo, after the
   checks. No secret is supplied in argv, clipboard, URL or logs.
3. A pinned-TLS challenge binds invitation digest, recipient, purpose and short
   expiry. The client proves possession of the one-time secret in an
   authorization header on that same pinned channel. The server atomically
   consumes the secret/challenge and returns a memory-only authorization ticket.
4. The ticket can mint at most three short-lived download grants for the one
   immutable archive. Each grant is consumed once. Only a classified transport
   interruption permits another mint; bad TLS, signature, hash, scope or policy
   is terminal. This permits bounded interruption recovery without reusing a
   consumed download grant or weakening submission replay controls.
5. The client validates all downloaded bytes, approved engine paths/profiles,
   session config and held file leases before the shared standard-user run.
   Existing submission token, nonce, privacy/schema, encrypted offline evidence
   and receipt checks remain. The separate private submission capability must
   be consumed for HTTPS nonce authorization or offline import.

These are bearer/one-time assessor capabilities, not proof of uncompromised
hardware. A stolen complete independent handoff requires revocation/reissue.
An optional managed non-exportable endpoint identity remains a separate future
enrollment option; the implemented pilot option is the ADR's one-time private
assessor handoff. Do not claim simulated identities or handoffs as REAL.

## Production gate and proofs

Ordinary sessions start TRUST_ENROLLMENT_PENDING. Legacy downloads require an
explicit localhost-assessor development opt-in and exact source-address list.
Pilot/release approval comes from independently provisioned protected policy /
approval evidence, verified publisher/Lab signatures and final code signatures;
it cannot be asserted by a browser flag or session JSON. Test-only independent
fixtures remain TEST_ONLY and cannot enable customer production distribution.

A protected, signed per-submission Lab trust receipt binds the accepted receipt,
evidence digest, envelope, authenticated metadata digests/key identities, TLS,
transport and assurance. It proves server-verified authorized provenance, not
remote attestation of execution. Legacy and test-only evidence remain distinct.

Issuance reserves PREPARING in the ledger before cross-file effects. Publishing,
session allowlist registration and auditable preparation precede READY. Failure
stays nonconsumable with a safe reason; reconciliation preserves consumed rows
and requires a new envelope. No filesystem/SQLite cross-domain atomicity is
claimed. Details and failure-injection evidence accompany the handoff.
