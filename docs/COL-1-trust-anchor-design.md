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
