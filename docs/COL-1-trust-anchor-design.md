# COL-1: independent investigation and proposed trust anchors

Status: **design proposal, architecture approval required**. No runtime trust-model
change is included in Independent Audit Correction A. Release remains HOLD.

## Verified current behavior

The unsigned EXE session package has a SHA-256 value in its appended trailer.
`build_bound_collector()` writes that value from the same archive. Production
`Program.cs` verifies it and hashes each extracted entry against the manifest
inside that archive. These checks detect corruption and changes made without
updating the corresponding hashes. They do not establish an independent publisher.

Windows regression
`CollectorBootstrapTests.test_col1_self_supplied_digests_do_not_establish_publisher_authenticity`
changes a harmless synthetic module comment, updates the module size/hash in its
manifest, and rebuilds the archive/trailer through the existing builder. The
production extraction verifier accepts the result. The adjacent unchanged-manifest
tampering regression rejects the modified module. This distinguishes byte
consistency from publisher authenticity without executing a changed Collector.

The script ZIP likewise includes its own manifest. The one-file PowerShell
launcher carries its archive digest, manifest digest, TLS pin and signer requirement
in the launcher binding. Its initial signature check currently permits NotSigned
when no signer is required. An attacker able to replace that unsigned launcher can
also replace these binding values. A pin delivered solely inside a replaceable
artifact is not an independent initial identity anchor. This conclusion follows
from `collector_launcher.py`, `Start-CSACollector.ps1.in` and
`collector_package.py`; the executable regression above is the empirical proof
for the unsigned EXE path.

This does **not** show that a passive network observer can defeat an intact TLS
pin, enrollment authorization, replay checks or signed receipts. The demonstrated
precondition is replacement of the unsigned distribution artifact and its own
digests. Receipts prove acceptance by the recorded Lab identity; they do not prove
that an independently trusted publisher supplied the endpoint code. Evidence is
also not remote attestation of an uncompromised endpoint.

## Authenticode boundary that still needs a signed build experiment

The build can sign the stable EXE stub before per-session package appending.
We have not tested a production certificate or the validity/coverage of the final
appended signed executable. Do not claim that its appended archive is protected
merely because the original stub had a signature. Microsoft documents that PE
Authenticode hashing excludes specific areas and depends on the image layout;
verification must use the **final distributed file**. Signed and unsigned paths
must be evaluated separately. No certificate or root was installed for this task.

References checked 2026-10-28:

- [Microsoft: Understanding executable file signing](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures)
- [Microsoft: PE format, Authenticode image hash](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#appendix-a-calculating-authenticode-pe-image-hash)
- [Microsoft: PowerShell signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing)

## Proposed design for review

Separate two authorities: the **publisher authorizes Collector code**; the
**assessment owner authorizes session configuration and destination**. A signature
from an arbitrary Lab key cannot become publisher authorization merely because
that key is bundled with the package. Never ship a publisher private key in Lab,
the launcher or a session package.

1. Publish a static, independently authenticated bootstrap for EXE and PowerShell.
   Embed an immutable publisher verification public key/key ID in authenticated
   bootstrap code. Verify the final release artifact through the OS/publisher
   distribution chain before execution. Decide the enterprise distribution and
   trust provisioning process explicitly; self-checking an unsigned file is
   insufficient.
2. Sign a canonical publisher engine manifest covering every executable script,
   module, schema, profile and privacy policy, including path, byte size, SHA-256,
   engine version and allowed schema/profile versions. The signed immutable code
   verifies it before any packaged code is imported. Both transports use the same
   verification library and refuse an unsigned or unknown-key downgrade.
3. Define a separate session manifest covering assessment/session IDs, expiry,
   archive/engine/profile digests, privacy policy, TLS identity, intended server
   and allowed submission policy. It must be signed by a Lab identity authenticated
   **independently of that manifest**. Architecture must select enterprise key
   provisioning or a publisher-authorized Lab delegation/enrollment flow, including
   the offline case. The existing per-session self-signed TLS pin is not sufficient
   for this first-contact authentication by itself.
4. Bind the enrollment credential to the approved session and destination;
   retain short expiry, replay/nonce checks, secure staging, privacy enforcement,
   bounded lock retries, offline encryption and signed receipts. Logs report safe
   verification reasons without credentials or identifying evidence.
5. Define key IDs, dual-key rotation windows, revocation/disconnected-operation
   rules, expiry/clock handling and rollback prevention. Unknown/revoked keys,
   malformed or duplicate paths and signature/digest failures stop execution.
   There is no silent fallback to the legacy unsigned path.

## Approval decisions and validation before implementation

- Choose initial publisher trust provisioning and Lab identity authentication.
  Confirm Home, enterprise compatibility and disconnected Lab requirements.
- Decide migration for existing unsigned installations and per-session EXE
  appending; choose an authenticated container format whose signed coverage is
  unambiguous. Verify final Authenticode status and PE overlay behavior on Windows.
- Keep issuer/private keys in controlled signing infrastructure, separate from
  ordinary Lab installs; define operational ownership and recovery.
- Add cross-transport tests for simultaneous module/manifest/archive replacement,
  substituted Lab identity/TLS pin, signer downgrade, expired and replayed sessions,
  wrong profiles, key rotation/revocation, malformed paths and interrupted downloads.
  Include Windows execution-policy and endpoint-security lock integration tests.

Until those decisions are accepted and implemented, report recorded session
allowlist membership separately from independent publisher authenticity. Audit A
does that; it does not resolve COL-1 by renaming a digest check.

## 5.6.4 decision proposal for architecture review

**Preferred path.** Build one immutable EXE and one signed PowerShell entry
point per release. Publish their final signed bytes through a trusted publisher
channel or enterprise-managed software deployment. Deliver the session as a
separate data file with a Lab-signed envelope. Bind the exact engine manifest,
Lab identity and TLS pin, destination, session and assessment IDs, profile,
expiry, mode and recipient to the signature. The launcher accepts only the
supported envelope schema and verifies it before unpacking or importing code.
Keep download and submission credentials short-lived and out of provenance logs.

| Option | Risk and implementation effort |
| --- | --- |
| Keep mutating or signing each session EXE | High operational risk. Requires online access to signing for routine sessions or relies on ambiguous Authenticode coverage of the appended overlay. Every session produces different bytes and hashes. Low migration effort, high ongoing cost. |
| Immutable signed launcher and separate signed session envelope | Medium migration effort. Stable artifacts can be distributed ahead of time, verified independently and evaluated by reputation systems. Requires a Lab identity provisioning and rotation lifecycle. |
| Enterprise-managed deployment and Lab trust provisioning | Low first-contact substitution risk for managed fleets. Higher operational effort per organization. Use the same immutable launcher and session format so HOME and disconnected workflows remain possible. |

1. **Provision trust before first use.** Obtain the publisher through the
   enterprise trust store or a verified release channel. Provision the Lab key
   or its signed delegation through enterprise configuration or an authenticated
   out-of-band assessor channel. For a self-signed portal, compare the full Lab
   fingerprint or import the trust record via that independent channel. A portal
   download or the contents of its own warning page cannot bootstrap that trust.
2. **Build and sign the final release bytes.** Use hardware-backed keys or a
   restricted signing service with short-lived CI identity, protected approvals,
   separate test and release policies, and audit logs. Retain the source commit,
   dependency lock and build recipe, unsigned reproducibility comparison,
   signed SHA-256, certificate chain, trusted timestamp and provenance record.
   Verify the final bytes and trust chain on clean Windows systems. Label unsigned
   test artifacts and keep them outside the release channel.
3. **Authenticate before executing.** Check publisher, then independent Lab
   identity and signed session scope, then package digest and publisher manifest.
   Validate TLS pinning and destination before credentials are transmitted. Start
   collection at standard privileges and require the session-bound nonce and
   authenticated receipt. For disconnected use verify against the preprovisioned
   identities and defined revocation freshness limit, then use encrypted offline
   submission with server-side verification on import.
4. **Prove the migration.** Test final Authenticode validity before and after
   appending a synthetic session to a test-signed EXE, plus replacement of the
   portal, envelope, trust records and package. The existing per-session layout
   changes the final file hash. Its signed coverage and acceptance depend on
   the final PE layout and Windows verification, so the proposal removes the
   overlay from the signed distribution format. Exercise SmartScreen, Smart App
   Control and enterprise endpoint protection with unchanged policy. Signing can
   reduce warnings. Endpoint enforcement and reputation can still block execution.
5. **Review before activation.** Require architecture approval, malicious-input
   tests and Windows LAB/HOME acceptance before retiring the unsigned transport or
   enabling the explicit-consent elevated BitLocker helper. Keep public release
   HOLD pending COL-1 and the other audit blockers.

SmartScreen evaluates publisher and file reputation. Smart App Control can
block malicious or potentially unwanted apps and uses signature validity when
its cloud assessment is uncertain. Enterprise antivirus can still scan the
package as it is written and evaluate runtime behavior, including for signed
code. Preserve narrow file-lock retries and normal endpoint enforcement.
[SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
· [Smart App Control](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions)
· [Defender behavior monitoring](https://learn.microsoft.com/en-us/defender-endpoint/behavior-monitor)
