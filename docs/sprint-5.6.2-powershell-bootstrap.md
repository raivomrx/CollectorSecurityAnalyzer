# CSA 5.6.2 — One-file PowerShell Collector bootstrap

Review candidate. Architect review and live customer acceptance are pending;
commit/push and installer artifacts do not create a final release/tag.

## Operator workflow

The Lab Join portal offers:

1. **CSA Collector (.exe)** — default/Home.
2. **PowerShell Quick Start (.ps1)** — recommended Lab/enterprise alternative.
3. **PowerShell Offline Package (.zip)** — manual/offline fallback.

Save `Start-CSACollector.ps1`, open a non-elevated **Windows PowerShell 5.1**
window in the download folder and run:

```powershell
.\Start-CSACollector.ps1
```

The script downloads, verifies and unpacks the session's existing Collector
package, invokes its unchanged collection/submission engine, and cleans up the
restricted staging tree. No manual ZIP extraction is needed. A new assessment
is recommended after updating Lab so its session package contains the new engine.
The ZIP can still be transferred manually and run with `Invoke-CSACollector.ps1`;
`-NoSubmit -ExportPath <path>` uses the existing encrypted offline workflow.
The launcher accepts the same explicit offline-export parameters, after its
initial authenticated online package download.

Do not change execution policy, remove Mark of the Web or disable endpoint
protection to make the launcher run. Existing organization restrictions apply.
Unsigned candidates may be blocked by RemoteSigned for browser-downloaded files,
AllSigned, AppLocker or WDAC. Contact IT for an approved signed build. This feature
is an alternative transport, not a way around application control.

## Trust and authorization

The EXE, launcher and ZIP use the same package bytes, session configuration,
enrollment token, TLS certificate pin, collection/privacy profile and submission
schema. Lab checks that the ZIP exactly matches the EXE's bound archive before
issuing a launcher. The session-bound launcher embeds the archive SHA-256,
manifest SHA-256, size, IDs, profile digest, certificate fingerprint and expiry.
Its initial trust comes from the authenticated Lab download/operator trust and,
when configured, Authenticode. An unsigned launcher is not an independently
signed trust root; editable digests alone do not establish publisher authenticity.

Only a separate random **download-only credential** is embedded in the launcher.
It is sent in the `CSA-Launcher` Authorization header to the fixed
`POST /api/v1/collector-package` route. No enrollment/download credential is put
in a URL, command-line argument, progress log or portal HTML. The enrollment
token stays inside the existing trusted package. The existing opaque Join-page
URL remains unchanged; the automated package request does not reuse its code.

The new route shares session state, source subnet, expiry, throttling and the
atomic download budget with the existing portal. Obtaining the launcher and its
package consumes two download slots. Restarting the listener rotates the
launcher download credential; old launchers must be downloaded again. It cannot
be used for evidence submission or for another assessment. HTTP redirects are
rejected, response sizes are bounded, TLS 1.2 and the exact session certificate
are required, and certificate validity dates are checked. No trust-store entry
or global TLS-validation override is installed.

## Integrity, file locks and cleanup

Before any package file is created, the launcher verifies the complete archive
and manifest digests, validates the entire Windows-safe inventory, rejects
case-insensitive duplicates, path traversal, ADS/device names, symlink/reparse
entries, missing/extra entries, malformed sizes and excessive expansion. Each
entry is hashed while its bytes are extracted and compared to the trusted
manifest. Manifest/configuration IDs, server pin/origin, profile digest, expiry,
standard-user mode and active-validation exclusion must match the launcher.

The temporary directory is created atomically with a protected ACL granting only
the current SID and SYSTEM. All child-engine TEMP/TMP staging stays inside it,
including evidence/session material and compiler temporaries. Cleanup operates
only on that unique launcher directory and reports failure explicitly. Managed
credential references and archive bytes are cleared best-effort; the operator's
intentionally downloaded launcher remains on disk and should be deleted after
use. It expires with the session. No plaintext evidence is retained as an
unrequested fallback. Encrypted export is written only to an explicit path.

Only Windows sharing/lock errors 32/33 receive the established bounded delays
(250, 500, 1000 and five 2000 ms waits). `TRANSIENT_FILE_LOCK` explains endpoint
scanning; persistent locks end as `CSA-BOOT-FILELOCK`. A lock never counts as a
successful verification. Digest, trust, path and access-denied failures are not
retried. Necessary Authenticode reads hold a shared handle, preventing an
exclusive scanner race during signature verification. The existing shared
runner applies the same signature checks to all three transports.

Network interruption produces `CSA-BOOT-NETWORK` before collection; the operator
can retry while the session remains active. Expired/disallowed credentials,
wrong TLS identity, altered packages/manifests and invalid/required-but-missing
signatures fail closed. Child collection/submission failures retain a nonzero
exit and the existing diagnostic; they are never reported as successful receipt.
Elevated/SYSTEM execution is refused and the shared engine independently requires
medium integrity. No new privilege adjustment, user-policy change, IEX workflow,
endpoint installation, persistence or active security validation is introduced.

## Authenticode configuration

Build scripts stage copies of Collector sources and Lab PowerShell helpers,
including the dynamic signing helper, and sign `.ps1`/`.psm1` files
with the existing CI signing certificate when supplied. Sources are not modified.
Signed bytes are bundled before session manifests are generated; the manifest
records the required module signer. Invalid or wrong publisher signatures are
rejected even when file digests match. Without signing material the build remains
explicitly unsigned; no trusted publisher or self-signed root is silently added.

Because a launcher contains dynamic session data, it must be signed **after**
generation. An assessor can configure `CSA_LAUNCHER_SIGNING_THUMBPRINT` with the
40-hex thumbprint of an approved code-signing certificate (with a private key) in
the Lab account's `Cert:\CurrentUser\My` store. The private key remains in that
store and is never bundled into an installer, launcher or Collector package.
The signing helper uses a restricted temporary directory. Configured signing
failure stops issuance; it does not fall back to unsigned output. Static module
and dynamic launcher signing may use separate approved certificates.

References: [execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1),
[Authenticode signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature?view=powershell-5.1),
[atomic directory ACL creation](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo.create?view=netframework-4.8.1).

## Validation boundaries

Python regressions exercise the real HTTPS portal, identical EXE/ZIP bytes,
credential scoping/rotation, source/expiry/budgets, altered archives/manifests,
entry hashing, unsafe paths, wrong TLS pin, a mid-stream disconnect, invalid
signature claims, a separate process holding a module for several seconds and
persistent locks. A synthetic collection fixture drives the production shared
runner through nonce/HMAC/package validation, submission and analysis. Its hosted
runner privilege/collection fixture is explicit test code; production has no
such bypass switch. Pester separately exercises elevation rejection, signature
states, ACLs, lock-only retries, cleanup boundaries and execution-policy invariants.

The optional self-hosted standard-user live workflow additionally runs the
actual one-file launcher under the account's existing execution policy. Only
identifier-free summaries are uploaded; raw host evidence stays local. Hosted
CI synthetic tests do not declare customer or two-computer live acceptance.

The installer workflow builds the EXE/Lab/NSIS package, verifies required bundled
launcher assets and runs the packaged Lab against an isolated empty data root.
This checks packaged startup/HTML/API behavior, not a silent install over an
existing user installation. Manual installation and endpoint/application-control
acceptance remain required before a public release.

Compatibility: evidence schema, collection profile/mandatory coverage, ACC-011,
CVE-001 presentation fix, CVE applicability/source trust, KEV priority, risk model,
BitLocker semantics, privacy controls and submission authentication are retained.
Product, Collector, report, analysis and installer identifiers align to 5.6.2.

## Local validation — 2026-10-27

- Full Python suite: **558 passed**, 0 failures/skips, with ResourceWarning
  treated as an error. Negative provider fixtures intentionally log simulated
  warnings/errors; these are not successful live upstream lookups.
- Full Pester suite: **107 passed** under Windows PowerShell 5.1 and **107 passed**
  under the PowerShell 7 CI host, with 0 failures/skips in both runs.
- Four framework content packs passed strict source validation.
- Collector/Lab/NSIS builds passed; required launcher/signing assets are bundled.
  Packaged 5.6.2 localhost HTML/API smoke passed with an isolated empty data root.
  Signing credentials are unavailable locally: installer and generated launcher
  remain explicitly unsigned. Positive organization-certificate deployment is
  still an acceptance check; invalid signatures and configured signer failures
  are covered by regressions.
- A real localhost launcher run under the existing RemoteSigned policy completed
  collection, authenticated submission, analysis and endpoint reporting without
  UAC/elevation. The measured process was MEDIUM / ADMIN_MEMBER_NOT_ELEVATED.
  This proves the non-elevated flow, **not** true non-admin-account acceptance.
  Private host evidence stayed in ignored restricted local acceptance storage;
  it is not committed or uploaded. Temporary-directory leakage was zero.
- Pure standard-user-account, browser-download Mark-of-the-Web, organization
  code-signing/AppLocker/WDAC and remote two-computer/customer acceptance remain
  pending. No final release/tag is created by this delivery.
