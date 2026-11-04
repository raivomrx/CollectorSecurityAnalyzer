# ADR 565 · PowerShell Copy & Paste trust

**Status** Proposed. Project lead and Architect approval required before protocol
implementation. CSA 5.6.5 ships a disabled Join preview. Release HOLD.

## Decisions for approval

1. **Publisher distribution.** Provision a small immutable CSA Quick Start
   verifier through the organization's managed Windows software channel. Its
   Authenticode signature, signing chain and publisher key are checked during
   provisioning. Install it in a fixed protected location with its publisher
   trust policy. Use this same mechanism for the first controlled LAB/HOME
   pilot, with an assessor-provisioned, independently verified installer.
   The project lead must nominate the distribution channel and signing operator
   and approve the initial publisher key fingerprints before enrollment.
2. **Lab first contact.** Preprovision a Lab trust record through managed device
   configuration. For a self-signed pilot, use a separately authenticated
   assessor channel to deliver the same record and the fixed command template.
   Match the full SHA-256 leaf certificate fingerprint against the assessor's
   own CSA Lab display before accepting that portal origin. Match the Lab
   signing key fingerprint independently as well. Approve the enrollment
   channel, Lab identity owner and recovery contact for each deployment.

An organization-trusted HTTPS Join page can supply the command after the above
enrollment. A self-signed Join page can supply it only once its exact identity
has been verified independently. If the operator cannot establish that identity
in the browser, obtain the command directly through the authenticated assessor
channel. Use the existing approved transport while enrollment is pending.

## Why the command origin matters

A substituted Join page controls every character the operator can copy.
It can replace an entire one-liner, including any apparent validation step.
Authenticode on a legitimate downstream payload protects that payload. The
command itself needs an authenticated origin before the operator pastes it.
A page-supplied fingerprint, forwarded header, join code or HTTPS scheme alone
provides no independent proof of command provenance. CSP and escaping control
injection on the genuine page. A different server can supply a different page
and different security headers. The pilot must demonstrate this boundary.

The local verifier provides a second security boundary for the legitimate
command. The command invokes a fixed protected path and passes only opaque
public locators for the enrolled Lab and assessment session. Locators use a
strict ASCII alphabet and length limit, convey no authority, and are never
derived from display names or a request Host header. The trusted local Lab
record supplies the origin. IPv4, bracketed IPv6 and explicit ports are parsed
as structured origin data, outside PowerShell syntax. The generated command
uses fixed quoting and a single shell invocation, and contains no enrollment
token, join code or download credential. The approved page will copy the
rendered text directly, with a selectable text fallback for denied clipboard
access. No browser action launches code.

## Proposed trust sequence and signed objects

Use the stable verifier to perform the first checks. It obtains the immutable
release `Start-CSATrustedCollector.ps1` from the preprovisioned publisher HTTPS
origin with OS chain/hostname validation, no redirects, bounded size and time,
and restricted per-run storage. Verify the **final file** using Windows
Authenticode chain, code signing EKU, trusted timestamp policy, revocation and
the locally allowed publisher SPKI SHA-256 pins. Check the exact bytes against
the verified publisher release manifest and enforce the minimum allowed release
sequence before starting any downloaded code. Run Windows PowerShell 5.1 as the
current standard user. A process-scoped `Bypass` is permitted where effective
organizational policy allows. Windows policy denial stops the workflow.

For review, use detached CMS SignedData with SHA-256 and RSA PKCS#1 v1.5
with keys of at least 3072 bits, over versioned canonical JSON bytes (RFC 8785 JCS).
Use distinct signing identities and object types for publisher and Lab.
Reject duplicate/unknown fields, unsupported algorithms and schemas, multiple
signers, noncanonical encodings, wrong signing roles, keys absent from local
policy, and objects outside their validity windows. Treat received certificate
material as chain input only. Policy and pins originate in local enrollment.

| Object | Verifier and authority | Required binding |
| --- | --- | --- |
| Publisher release manifest | Local verifier using publisher policy | Object type and version, release ID and sequence, build commit, validity, starter byte size/SHA-256, exact paths/byte sizes/SHA-256 of authorized immutable engine scripts, modules, schemas and approved default profiles/privacy policy |
| Lab trust record | Managed enrollment or verified assessor channel | Stable Lab ID, active Lab signing key ID and SPKI fingerprint, exact HTTPS origin, TLS identity/leaf pins where applicable, policy version, validity and revocation freshness limit |
| Lab session envelope | Authenticated starter using local Lab record | Object type and version, Lab key ID, assessment/session and recipient or scope, issue/expiry times, envelope ID, exact HTTPS origin/TLS pin, submission mode/destination, publisher release/manifest digest, profile/privacy digests, archive digest and session-bound manifest digest |
| Endpoint authorization grant | Lab after successful session and endpoint authorization | Authorized endpoint, session, challenge, expiry, purpose and separate download/submission scopes |

The authenticated starter first checks Lab identity and TLS, then retrieves and
verifies the signed envelope by public locator without sending session secrets.
Compare its assessment, session, origin, destination, TLS pin, profile/privacy
and release authorization with locally trusted policy. The Lab authorizes the
endpoint only after these checks. The managed path uses a preprovisioned,
non-exportable endpoint identity to prove possession on a fresh Lab challenge
bound to the verified envelope. A controlled pilot without that identity can
use a one-time secret delivered through the assessor channel and entered in a
secure prompt after verification. Both paths require explicit assessment scope.
Consume challenges and one-time grants atomically. A multi-endpoint session
envelope can be read by multiple endpoints while each authorization and
submission keeps its own replay boundary. The public locator cannot exchange
for a credential on its own.

Keep the download grant in memory and send it only in an authorization header
over the pinned Lab channel. Bind the existing enrollment/submission credential
to the same assessment, session and destination. Keep it out of argv, URLs,
HTML, clipboard, history and logs. If the existing engine requires staging its
configuration, write it only in a unique restricted work directory, protect it
against overwrite/reparse substitution, and remove it with the package on exit.

Verify the archive and existing session manifest against the signed Lab envelope.
Require **every executable path** and its exact bytes to match the publisher
manifest, including bundled scripts that the shared engine imports. Allow only
the enumerated session data files, whose sizes and digests the Lab envelope
authorizes through the bound manifest. Use the existing path, duplicate, size,
stream-hash and bounded sharing-violation checks. Keep verified files protected
from replacement through invocation. Execute the shared engine only after these
checks. Preserve its schema, privacy-before-write, privilege, nonce, exact TLS
pin and receipt-binding logic. The existing online response is authenticated
by pinned TLS and checked for matching submission, package digest and acceptance.
Keep the server-side signed receipt and audit trail as separate evidence.

Report trust, download, verify, collect, submit and cleanup phases without
credentials. Use `CSA-TRUST-PUBLISHER`, `CSA-TRUST-LAB` and
`CSA-TRUST-SESSION` for trust rejection. Only classified transient network or
Windows sharing/lock failures qualify for bounded retry. Stop on trust or digest
failures. A cleanup failure gets a distinct `CSA-BOOT-CLEANUP` outcome.

## Key lifecycle and migration

- Keep publisher signing in controlled signing infrastructure with short-lived
  CI identity, scoped release approvals, timestamping and audit records. Store
  the signed manifest, final artifact SHA-256, signer chain, build commit and
  toolchain provenance. Keep isolated test identities in ephemeral test stores
  with no production-policy trust or private keys in CI artifacts.
- Create a distinct Lab signing key in the Windows protected key store, with
  access limited to the Lab signing identity. Enroll the public fingerprint
  through the approved channel. Rotate with a finite overlap after policy
  distributes the new key. Maintain expiry and a current revocation list through
  the authenticated provisioning channel. Keep backup encrypted under assessor
  recovery control or re-enroll with a replacement key. On compromise, revoke,
  stop affected sessions, replace both keys where implicated and re-enroll.
  Unknown, revoked, expired or stale trust state stops online Quick Start.
- Store minimum release sequence and current trust-policy version in protected
  local policy. Rollback requires a separately authenticated policy change
  authorizing specific release digests and a new review. An expired/revoked
  session, missing policy or bad signature cannot trigger a legacy downgrade.
- Keep 5.6.4-style session packages usable for authorized legacy LAB/offline
  runs under their original acceptance rules. The per-session EXE overlay and
  downloaded `.ps1` still have the documented COL-1 boundary. Operators select
  legacy or encrypted offline workflows explicitly. Pilot the new trust chain
  alongside them. Publish signed distributions after negative tests, final
  artifact verification, independent audit and LAB/HOME live acceptance.

## Validation required before enablement

Verify the final signed files and signer identity on clean Windows. Use isolated
test-only signers to test wrong publisher, tampering, unsigned replacement,
revocation, expiration, known rotation and rollback. Substitute the Join page,
Lab identity, TLS certificate, session envelope and self-consistent package in
separate cases. Exercise first contact, missing trust, policy denial, replay,
downloads under network interruption and transient scanner locks, and credential
absence in browser, command, process, storage, logs and artifacts. Then compare
the same synthetic inputs across transports and require a validated submission
and cleanup on both LAB and HOME before public release. Elevated BitLocker
verification requires its own approval.

[Existing COL-1 foundation](COL-1-trust-anchor-design.md)
· [PowerShell execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1)
· [PowerShell signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing)
· [Cryptographic Message Syntax](https://www.rfc-editor.org/rfc/rfc5652)
· [JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
