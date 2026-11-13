# ADR 5682 — controlled assessor pilot without production signing

Status: APPROVED for development by the project lead on 2026-11-11.
Customer authorization to use CSA is already confirmed.
This decision does not ask for that authorization again.

The project lead confirmed that production Publisher/Lab signing identities
and the independent delivery channel have not yet been selected. The existing
ADR 565 runner intentionally requires those identities. A preparation screen
alone cannot make that runner usable on a clean client.

## Concrete proposed exception

Introduce a separate assessor pilot transport, named
`ASSESSOR_VERIFIED_PILOT` in implementation. It is not DEVELOPMENT_UNSIGNED,
PILOT_APPROVED, or verified production Authenticode.

1. The assessor explicitly records the existing customer authorization
   reference, assessment/session, exact intended endpoint/source, approver,
   approval time and short expiry (no longer than the session).
2. Before execution, the assessor independently authenticates the exact
   immutable EXE/launcher and package SHA-256 through a separately approved
   handoff channel. The package must not supply its own trust anchor.
   The operator records which channel was used. Possession of a contract
   alone does not constitute a check of those particular bytes.
3. Use a private, recipient-bound handoff with an independently pinned
   assessor signing key and detached signed release/session metadata.
   An ephemeral or privately issued signing identity is labeled as such;
   it never counts as a production Publisher signature or a trusted
   Windows Authenticode chain. Do not install root certificates.
4. EXE and process-only PowerShell Quick Run use the same engine, profiles,
   privacy, signed metadata, exact Lab TLS pin and receipt/submission
   validation. Do not mutate a signed executable using a session overlay.
   Do not execute public portal download code on first contact. The
   independently authenticated bootstrap must hold verified input files
   against replacement through execution.
5. Keep this pilot portable where feasible: private temporary work files
   are removed after the one-shot run. Document any unavoidable one-time
   trust provisioning separately. No persistent execution-policy change,
   trust-store update, service, UAC elevation, or application-control
   workaround is allowed.
6. Require scoped one-use authority and fail on mismatch, expiry, wrong
   endpoint/session/source, replay or missing independent package identity.
   Never enable legacy endpoints as an error fallback. Windows security
   policy can refuse unsigned/private-signing artifacts; record the real
   refusal and return to the approved delivery owner.
7. Record this assurance as ASSESSOR_VERIFIED_PILOT in protected receipts,
   audit and reports. Preserve the separate production trust statuses.
   Keep public release HOLD. Real HOME/LAB acceptance remains required
   before claiming successful client execution.

## Scope of the confirmation

Approval authorizes implementation and negative tests of this separate
trust exception. It does not invent a key, independently checked fingerprint,
real endpoint acceptance result, channel record, or Windows signature.
Those must be supplied/checked for each actual handoff.

## November 13 Start-only delivery instruction

The project lead subsequently requires Start Collector alone to prepare both
mandatory customer methods. The [5.6.8.3 P0 correction](sprint-5.6.8.3-p0-live-fix.md)
documents the concrete implementation in delivery version 5.6.8.4: the local
assessor's Start action authorizes the selected bounded LAN/session scope using
the independently obtained Lab installation. Each Join source receives a sealed,
one-use standalone EXE and the hash/TLS-pinned Quick Run of that same EXE.
Automatic delivery uses direct LAN source binding, not a fabricated hardware
pin or production Publisher identity. Existing manual hardware-bound handoffs
remain separate. This operational update introduces no new signature protocol
and does not remove independent origin verification or protection enforcement.
Production trust and project-manager live acceptance are still pending.

Alternative: retain the existing signed-and-pre-enrolled transport and
complete its production identities/channel before client collection.
