# CSA 5.6.8: trusted distribution engineering handoff

Development approval: project lead and Architect, 2026-11-05, ADR 565.
**Public release HOLD. Actual publisher identity, key owner and independent
enrollment channel are pending. Copy command stays disabled.** A successful
engineering gate does not constitute HOME/LAB or customer acceptance.

## Distribution and execution

The new immutable `CSA-TrustedCollector.exe` and signed-compatible
`Start-CSATrustedCollector.ps1` are installed through an independently approved
managed deployment or assessor handoff. The PowerShell entry calls the same EXE
verifier. Both execute the existing `Invoke-CSACollector.ps1` and Collector
modules, without an execution-policy override, elevation or a separate engine.
No endpoint installation is attempted by the one-shot Collector itself.

The fixed locations are `%ProgramFiles%/CSA/Collector/` for the two immutable
files and `%ProgramData%/CSA/Trust/policy.json` for independently provisioned
policy. The CSA directories/files must be owned by SYSTEM or Administrators;
only those identities may write, delete, replace, change ACLs or take ownership.
Reparse points are rejected. Provisioning belongs to the authorized deployment
owner. The ordinary Lab installer does not enroll either identity or install
trust roots. A local unsigned build cannot bootstrap its own authenticity.

A private per-recipient bundle contains exactly these data objects:

| File | Authority/binding |
| --- | --- |
| `publisher-manifest.json` / `.p7s` | Publisher CMS signature over the immutable release and every authorized engine file |
| `session-envelope.json` / `.p7s` | Independent Lab CMS signature over session, recipient, destination, TLS, profile, privacy and package digests |
| `collector.zip` | Existing engine and session package; byte digest authorized by the signed envelope |

After enrollment and final signature acceptance, the independently delivered
command invokes the fixed installed path with `--bundle <private-folder>`.
Encrypted offline export adds `--offline <output.csa>`. The installed PowerShell
entry accepts `-Bundle` and optional `-OfflineExport` and invokes the same EXE.
Paths and the command itself must arrive through the authenticated handoff;
a web page cannot prove the origin of the command it supplies.

The current implementation deliberately accepts local handoffs. Automatic
network discovery/download and the ADR's endpoint proof-of-possession challenge
exchange are not exposed. The Join page has no runtime switch that can assert
endpoint enrollment and enable Copy. The authenticated locator workflow needs
its deployment acceptance before future enablement. This limitation does not
cause an unsigned download fallback.

## Verification order and wire objects

1. Refuse elevation and missing/unsafe/stale local trust. Verify the installed
   EXE with Windows WinVerifyTrust, including chain revocation excluding the
   trust anchor, and match
   its certificate and RSA SPKI against enrolled publisher policy.
2. Verify the publisher's detached CMS, signing role/key, certificate validity,
   release sequence and final EXE/entry byte digests.
3. Verify the separate Lab CMS against its independently enrolled SPKI. Match
   Lab ID, exact HTTPS origin, leaf TLS pin, session recipient and validity.
4. Verify the ZIP snapshot and session manifest. Every executable, module,
   schema and policy must match the publisher's exact path, length and SHA-256.
   Only four dynamic data files are allowed: config, TLS public certificate,
   offline public key and operator instructions. They are bound through the
   existing session manifest digest. Reject extra, missing, duplicate,
   case-conflicting, device-name, ADS, rooted and traversal paths.
5. Extract using the existing stream-hash verifier and classified lock retries.
   Compare actual configuration, privacy policy, TLS certificate, session and
   expiry with signed scope. Hold read leases on staged files until exit and
   compare bytes through those same handles with the authenticated archive.
   This final check closes extraction-to-execution replacement; classified
   scanner locks use bounded backoff, while a changed byte is a trust rejection.
6. Consume the local replay marker, then invoke the shared standard-user engine.
   Online submission consumes a server grant before issuing the existing nonce.
   Offline import consumes the same grant after decrypting/validating evidence.
   The existing pinned TLS, nonce, privacy/schema validation, encrypted offline
   format, receipt signatures and audit chain remain in force.

Signed objects use detached CMS SHA-256 with RSA PKCS#1 v1.5, keys >=3072 bits,
one signer, and schema version 1. Canonical JSON uses the RFC 8785 integer-only
subset: UTF-8 without BOM, UTF-16 ordinal key sorting, no normalization, no
duplicate or unknown fields, no floating-point values and no integers outside
the exact JSON-safe range. Noncanonical bytes are refused before trust use.
The existing evidence canonicalization/schema is unchanged.

| Object | Exact schema fields |
| --- | --- |
| `CSA_TRUST_POLICY` | `objectType`, `schemaVersion`, `issuedAt`, `expiresAt`, `revocationFreshUntil`, `minimumReleaseSequence`, `endpointId`, `publishers`, `labs` |
| Publisher policy key | `keyId`, `spkiSha256`, `certificateSha256`, `issuedAt`, `expiresAt`, `revoked` |
| Lab policy key | `keyId`, `spkiSha256`, `labId`, `origin`, `tlsFingerprint`, `issuedAt`, `expiresAt`, `revoked` |
| `CSA_PUBLISHER_RELEASE` | `objectType`, `schemaVersion`, `keyId`, `issuedAt`, `expiresAt`, `releaseSequence`, `version`, `commit`, `bootstrapSha256`, `bootstrapSize`, `entryPointSha256`, `entryPointSize`, `files`, `profiles` |
| Engine file | `path`, `size`, `sha256` |
| Approved profile | `profileId`, `profileDigest`, `privacyPolicyDigest` |
| `CSA_LAB_SESSION` | `objectType`, `schemaVersion`, `keyId`, `issuedAt`, `expiresAt`, `envelopeId`, `nonce`, `labId`, `recipientId`, `assessmentId`, `sessionId`, `origin`, `tlsFingerprint`, `mode`, `profileId`, `profileDigest`, `privacyPolicyDigest`, `publisherManifestDigest`, `packageDigest`, `sessionManifestDigest`, `submissionPolicy` |
| Submission policy | `transport` = `HTTPS_OR_ENCRYPTED_OFFLINE`, `maximumBytes`, `receiptRequired` = true |

CMS signature verification is cryptographic verification against independent
local key enrollment; it does not trust a CMS-embedded self-signed certificate
as a Windows CA. Publisher certificate bytes are additionally pinned. OS
Authenticode chain/timestamp verification is a separate mandatory distribution
check. A Lab key is an independently enrolled authority, distinct from both the
publisher key and the session TLS/receipt key. Cross-role SPKI reuse is refused.

## One-use authorization and privacy

Bundle authoring copies the existing package into restricted staging; the
original package and immutable launchers stay byte-identical. Only optional
`trustedEnvelopeId` and `trustedEnvelopeNonce` session-config data are added.
The package build digest is recomputed and explicitly registered with the
existing session allowlist. Issuance then requires a server grant for this
assessment/session. The nonce is at least 16 ASCII locator characters, generated
with Python `secrets` by the operator tool. No credential appears in argv,
URLs, clipboard commands or audit events.

The private handoff contains the existing short-lived enrollment credential and
the per-recipient capability. Deliver it privately through the approved channel;
do not attach it to GitHub or email it as a public artifact. Recipient IDs are
scope labels, not remote attestation or hardware possession proofs. Possession
of a stolen complete handoff remains a credential compromise and requires
session revocation/reissue. The automatic managed identity/challenge route is
not claimed by this delivery.

Server grants persist in per-session SQLite databases under
`sessions/trusted-grants/`. Transactions (`BEGIN IMMEDIATE`, five-second busy
timeout), unique envelope/nonce-digest constraints and conditional consumption
serialize grants across threads and processes. Only a SHA-256 capability digest
is stored in the ledger. A grant
can authorize one HTTPS nonce request or one encrypted offline import. The
existing evidence nonce still has its own binding/replay rules. Once a session
issues a trusted grant, legacy requests without one are refused. Concurrent
Lab receivers sharing one storage directory remain unsupported for the wider
existing session/index/audit storage. Close Lab before operator CLI authoring,
prepare the private bundles for the new assessment before Start Collection,
then reopen/start the single Lab receiver. Do not issue bundles with a second
CLI process while collection/analysis writes are active.

Failure after consuming a grant is conservative: the operator issues a fresh
envelope rather than resetting a used marker or reusing credentials. A lost
response, abandoned online attempt or interrupted cleanup cannot silently
reuse the same grant for offline import. Local replay markers are an additional
guard, not a substitute for server enforcement. Output receipts keep their
existing signatures and fields. Evidence checks and assessment/risk logic are
unchanged; report metadata adds separate provenance states.

## Signing/build and operator tools

- `scripts/Build-CSATrustedCollector.ps1`: compile both immutable entry files.
  The output is **UNSIGNED LAB ONLY** until approved final signing.
- `scripts/Sign-CSAArtifacts.ps1`: final-file Authenticode, approved publisher
  certificate digest, trusted timestamp, Get-AuthenticodeSignature and
  `signtool verify /pa /all /v`. Release builds require inputs and fail closed.
  PFX/password are never placed in argv; temporary signing material is removed.
- `scripts/New-CSAPublisherManifest.py`: controlled publisher host only. Accepts
  an approved engine package and the **already finally signed** EXE/PS entry,
  version, commit, monotonically increasing sequence, key ID, store thumbprint
  and approved certificate SHA-256. Checks final Authenticode status/timestamp
  and same signer, then signs immutable metadata with the external store key.
  Private publisher keys must not be present on Lab/client installations.
- `scripts/New-CSATrustedBundle.py`: authorized Lab operator uses an existing
  session package, publisher manifest/signature and separately provisioned Lab
  store certificate. Creates a restricted per-recipient data bundle and grant.
  Publisher artifacts and secrets are never modified or exported by this tool.
- `.github/workflows/trusted-release-gate.yml`: manual lane targeting
  `csa-release-approval`; repository owners must configure environment protection.
  Requires explicit release/enrollment approvals and pinned signing
  identity. It does not publish a release. Normal CI remains a development lane.

Read each tool's `--help` for named inputs. Public IDs/fingerprints/paths are
permitted arguments; enrollment credentials/private-key bytes are not. Keep the
publisher manifest and immutable files as one exact signed release set. Any
change after signing requires a new sequence, signatures and acceptance.
Unsigned legacy PE overlays cannot be produced from signed EXEs: the builder
rejects a PE certificate directory before appending any session data.

## Key lifecycle, clock and failures

Provision policy only through the independently authenticated approved channel.
Clock skew permits an issue time at most 120 seconds ahead; expiry has no grace.
Session envelopes last at most 24 hours and cannot extend session credentials.
Offline execution/import must still occur before their expiry. Policy requires
a current `revocationFreshUntil`, bounded by policy expiry. Offline clients do
not treat inability to refresh revocations as success. Publisher Authenticode
may also require Windows revocation services/cache; unavailable validation can
stop disconnected execution. This conservative limitation needs an explicitly
tested deployment policy, not a validation bypass.

Rotate keys by independently deploying the new policy before use, with a finite
overlap. Keep distinct key IDs and active validity windows; mark compromised
keys revoked, close affected sessions and re-enroll. Increase the protected
minimum release sequence to retire old engine releases. Revoked/expired keys,
stale policy and lower sequences stop both transports. Policy rollback is an
administrative trust operation requiring independent review. No unknown key or
revocation failure can trigger the legacy route.

Useful safe codes include `TRUST_NOT_ESTABLISHED`, `CSA-TRUST-PUBLISHER`,
`CSA-TRUST-LAB`, `CSA-TRUST-SIGNER`, `CSA-TRUST-CERTIFICATE`,
`CSA-TRUST-REVOKED`, `CSA-TRUST-EXPIRED`, `CSA-TRUST-STALE`,
`CSA-TRUST-ROLLBACK`, `CSA-TRUST-SESSION`, `CSA-TRUST-RECIPIENT`,
`CSA-TRUST-SCOPE`, `CSA-TRUST-DIGEST`, `CSA-TRUST-ENGINE`,
`CSA-TRUST-PATH`, `CSA-TRUST-REPLAY`, `CSA-COL-FILELOCK` and
`CSA-BOOT-CLEANUP`. Only classified sharing/lock violations use existing bounded
backoff. Signature/digest/path/trust failures are never retried as transient I/O.

## Incident diagnostics and report proofs

Defender alert and LAB portal error remain separate incident tracks. The local
development computer supplied no matching Defender 1116/1117 evidence for the
reported customer incident. Its detection/action and root cause remain unknown;
neither a false positive nor SmartScreen is inferred from the combined report.
Collect the affected file hash/signature, redacted Protection History detection
name/action or relevant event IDs, exact UTC time and the portal correlation
reference through authorized local storage. Separate Defender detection from
SmartScreen reputation, Smart App Control, WDAC/AppLocker and PowerShell policy.
Never disable protection or add broad exclusions to get a successful run.

Portal responses now carry `X-CSA-Correlation-ID`, `X-CSA-Stage` and event class.
Stable stages distinguish Join/download, package delivery, authorization,
validation and acceptance. Client errors provide a safe correlation reference
and bounded next steps; logs omit raw paths/URLs, join tokens, client IPs,
usernames and exception payloads. Malformed-request logging also rejects free
form text. Audit records use hashed source addresses.

The sanitized regression submits three valid evidence packages for two device
IDs, with a later repeat of the first. Result: **3 accepted submissions,
2 endpoints, 1 duplicate endpoint submission**. Three `submission_quarantined`
events mean CSA immutable staging before validation, each followed by acceptance.
They do not demonstrate a security-product quarantine. The UI adds this meaning
without altering stored event types or historical audit hashes. Acceptance audit
also records whether the endpoint was already present.

Report Integrity displays session allowlist membership, archive/file integrity,
publisher authenticity, independent Lab identity, recorded TLS pin, signed
receipt integrity and audit-chain integrity separately. Publisher authenticity
stays NOT_EVALUATED and Lab enrollment PENDING without independent recorded
proof; a valid allowlist or receipt does not upgrade these states. Offline
receipt verification expects its actual `ACCEPTED_OFFLINE` status.

## Acceptance still requiring real deployment

1. Nominate publisher certificate/key owner and protect signing service access;
   enroll independently verified certificate/SPKI pins. Verify final EXE, PS,
   engine scripts and installer with Windows chain/revocation/timestamps.
2. Nominate Lab signing owner, exact Lab/TLS identity, independent delivery
   channel, revocation refresh and recovery contacts. Deploy protected policy
   and installed verifier on clean Windows. No roots were installed by tests.
3. Author an actual signed publisher manifest and Lab bundle; exercise both
   entry points on identical synthetic inputs and compare evidence/checksums,
   online/offline receipts, one-use behavior, lock recovery and cleanup.
4. Perform same-candidate HOME/LAB acceptance on Windows 11 Home/Pro with real
   endpoint security and enterprise policy intact. Diagnose both original
   incidents using source logs. Obtain Architect/project-lead acceptance.
5. Independently review the enrolled command origin and endpoint authorization
   before exposing network Copy & Paste. The November 9 pilot has no exception:
   missing trust, signatures or acceptance means NO-GO for that transport.

## Engineering validation

Windows local validation: **627 Python tests passed**, no skips or resource
warnings, plus **116 Windows PowerShell 5.1 / Pester tests passed**, no skips.
The new trust module contains 18 tests, including Python-generated CMS and
Windows CNG/SignedCms interoperability, certificate/key replacement, wrong
signer, expiry/revocation, stale policy, rollback, unsafe/rehashed archives,
scope/TLS substitution, changed staged bytes, missing enrollment, release
signing denial, execution-policy refusal, online/offline receipts and thread/
process replay races. Eight isolated processes can consume a grant only once.
The existing multi-second Windows scanner-lock regressions also pass.

One earlier full run saw an isolated localhost HTTP connection abort in the
unchanged admin CSRF test. Its focused rerun (19 tests) and the final complete
627-test run passed. This is recorded as an intermittent test observation,
not a diagnosis of the reported LAB portal incident. No endpoint protection
or execution policy was changed to resolve it.

Both immutable files compile; the edited PowerShell scripts parse. Test
certificates/keys were ephemeral and no trust roots were enrolled. Real
publisher Authenticode, production revocation/timestamp services, positive
enrolled deployment and customer HOME/LAB tests remain the operational gates
listed above. Framework test skips of zero do not imply those live tests ran.

The exact commit CI results and installer hash/signing status are recorded in the
delivery handoff. Synthetic CMS positives/negatives do not claim successful
production Authenticode, revocation service availability or customer live tests.

References: [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html),
[WinTrust policy flags](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data),
[PowerShell signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing).
