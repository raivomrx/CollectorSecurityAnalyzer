# CSA 5.6.8.1 — correction and acceptance handoff

Public release: **HOLD**. Real Publisher, independent Lab, independently
confirmed TLS pin and independent trust channel: **TRUST_ENROLLMENT_PENDING**.
The regular CI installer is **UNSIGNED LAB ONLY**. No customer pilot exception.
The approved process-only Quick Run amendment is recorded in
[ADR 5681](ADR-5681-authenticated-quick-run.md).

| Correction | Implementation | Regression evidence |
|---|---|---|
| TD-C01 | `csa_console/distribution.py`, `server.py`, `portal.py`; `csa_lab/service.py`, `web.py`, `templates/lab.html`, `templates/lab.js`. Server denies all legacy routes by default and denies downgrade when any trusted issuance exists. | `test_architect_correction.DistributionBoundaryTests`; direct GET and POST, spoofed flags, restricted opt-in, existing development workflow. |
| TD-C02 | `collector/trusted/{TrustedEntry,TrustProtocol,TrustedNetwork}.cs`, `Start-CSATrustedCollector.ps1`, `collector/bootstrapper/Program.cs`, `csa_console/{quick_start,trusted_network,trusted_grants}.py`, `csa_lab/trusted_distribution.py`, `scripts/{Build-CSATrustedCollector.ps1,New-CSATrustedBundle.py}`. Two commands, same engine, signed invitation and pin, private one-use authorization, short one-use grants, integrity-before-execution. | `test_trusted_network` and `test_trusted_distribution`: isolated Windows HTTPS/CMS, real shared PowerShell entry with synthetic acquisition, both modes submit, privacy enforced and policy unchanged, refusal/replay, interrupted download and no retry on bad digest. Not real Authenticode enrollment. |
| TD-C03 | `collector/trusted/TrustInspection.cs`, `csa_lab/trust_authority.py`, existing `trusted-release-gate.yml` and signing lane. Independent ACL, native Authenticode and detached signature verification. | Source/fixture checks; legal identities, key custody, channel and clean HOME/LAB validation **pending**. Follow runbook below. |
| TD-C04 | `csa_console/{trust_evidence,trust_receipts,submission,offline,integrity}.py`, `csa_lab/templates/unified.html`. Separate archive, session allowlist, signed receipt, Publisher, Lab, TLS and audit conclusions. | Windows TEST_ONLY receipt, modification and legacy/mixed-state tests. Each row displays what was verified; no client self-claim promotes a status. This record is authorization/provenance, not execution attestation. |
| TD-C05 | `csa_console/{server,submission,offline}.py` and protected audit trail. Separate staging/rejection/acceptance/analysis failure. | Malformed input, missing/invalid enrollment token, searchable correlation on 4xx/5xx, accepted evidence with failed analysis, existing immutable staging/dedup. Reported endpoint incidents **NOT_EVALUATED**. |
| TD-C06 | `csa_console/trusted_grants.py`, `csa_lab/trusted_distribution.py`, `scripts/Reconcile-CSATrustedIssuance.py`. Durable PREPARING/READY/FAILED, reason and reconcile/reissue. | Failure injection for interrupted signing/publication, disk full, audit, duplicate ID, ledger-only/session-only, consumed markers and new grant. |
| RC-C01 | `csa_lab/templates/unified.html`, existing BitLocker presentation semantics retained. | `test_report_clarity`: Shell 1 / 2 reported ON, separate confirmed and unresolved counts, raw 0 does not establish OFF. |
| RC-C02 | `csa_lab/unified_report.py`, `csa_lab/templates/unified.html`. Per-control evidence and reevaluation guidance separate from confirmed remediation. | HTML 1/2/10/50/100 endpoint scales, escaped UTF-8, exact rule and endpoint links; CVE/KEV regressions. |

## Upgrade and operator paths

- **Ordinary session:** Join shows trust pending and both Copy actions disabled.
  Guessed legacy routes and v2 URLs cannot change this. A prior unsigned
  assessment can be used for internal development: pause first if running,
  open **Settings → Distribution**, enable restricted development, enter the
  exact authorized assessor client IP addresses, and start/resume. The
  listener subnet still applies; use a separate development assessment if
  trusted issuance has ever been attempted. Pause or disable the setting to
  revoke the legacy routes. Existing accepted data does not need migration.
- **Signed v1 local handoff:** private and data only, using the independently
  installed verifier and `--bundle`. Keep the archive and envelope private.
  It remains suitable for preliminary HOME/LAB qualification only after real
  independent enrollment. No new trust can be established by unpacking it.
- **Signed v2 HTTPS:** an assessor uses `scripts/New-CSATrustedBundle.py --network`
  from the authorized Lab with the exact session package and publisher
  manifest/signature. See `--help` for required storage/assessment/session,
  output, Lab signer and recipient arguments. The output directory must be
  private, outside shared/web folders and retained under operator access only.
  Deliver `assessor-authorization.txt` separately over the approved private
  channel. Never publish it, paste it into the command, include it in logs,
  send it in an unapproved ticket or persist it on the endpoint. Issue a new
  invitation if it was exposed, expired or consumed.
- **Endpoint:** from an independently authenticated Join command or assessor
  handoff, paste once into a standard-user Windows PowerShell window. Use
  **PowerShell Copy & Paste** for local execution policy or **Quick Run –
  ExecutionPolicy Bypass** for the approved process-only alternative. The
  unchanged Windows protections still decide whether the engine can run.
  Enter the private code in the hidden prompt only after verification. A
  browser clipboard permission error selects the command for manual copy.
  If organization policy blocks the run, record the code and Windows event;
  do not request elevation or alter application control or protection.

An interrupted issuance is not a reason to delete or edit the SQLite ledger,
clear local used markers, or enable development. Close Lab, preserve the
protected data root, then run
`scripts/Reconcile-CSATrustedIssuance.py --storage <root> --assessment <id> --session <id>`.
The tool reports operation state/reason and never resets consumed grants.
Remove any abandoned private output only after the assessor has reviewed it.
Issue a fresh envelope and private code; there is no cross-store atomic commit.

## Independent enrollment and signing

1. The project lead and Architect record the publisher legal entity, signing
   key owner and custody, exact certificate DER SHA-256 and RSA SPKI SHA-256
   sources, Lab signing key owner and SPKI source, and independent delivery
   channel owner. Use the approved managed software channel or independently
   verified assessor handoff. Record signer chain, time stamp authority,
   certificate/revocation check and enrollment evidence in the protected
   operator register. These values are **unselected** for the real pilot.
2. Sign final EXE/PS/installer in the protected release lane. Verify
   `Get-AuthenticodeSignature -LiteralPath <artifact>` shows `Valid` and the
   approved signer and a time stamper; verify `signtool verify /pa /all /tw
   <artifact>` with revocation connectivity on clean Windows. Independently
   compare `Get-FileHash -Algorithm SHA256 -LiteralPath <artifact>` and the
   certificate/SPKI pins with the operator register. Only then author the
   detached publisher manifest for the exact final EXE/PS and engine/profile
   bytes. Do not modify signed artifacts afterwards. Do not enroll from the
   Join page, bundled metadata or the development installer.
3. An authorized administrator or managed channel installs the two immutable
   files `CSA-TrustedCollector.exe` and `Start-CSATrustedCollector.ps1` in
   `%ProgramFiles%\CSA\Collector\`. Independently install the endpoint
   policy at `%ProgramData%\CSA\Trust\policy.json` and, on Lab, the per-recipient
   policy and approval under `%ProgramData%\CSA\Trust\recipients\<recipient>\`.
   Secure every CSA path component and file: owner SYSTEM or Administrators,
   only those principals can write, change ACL/owner, add or delete;
   grant standard users read/execute only as needed. Inspect owner/DACL with
   `Get-Acl -LiteralPath <path>` and attributes with
   `Get-Item -LiteralPath <path>`; reject links/reparse points and inherited
   writable ACEs. Prove a standard-user token cannot modify, replace or
   rename any enrolled file. Installation is a separate administrator task;
   collection runs as standard user.
4. The endpoint `CSA_TRUST_POLICY` canonical JSON contains version, validity,
   revocation freshness deadline, endpoint ID, minimum release sequence,
   pinned Publisher key IDs/SPKIs/certificate hashes and Lab key IDs/SPKIs,
   Lab IDs, exact HTTPS origin and session certificate fingerprint, per-key
   windows and revocation flags. Provision the Lab policy for the same
   recipient. Verify the current session TLS pin independently of Join.
   Rotate before expiry and provision a new policy/approval/invitation for
   a new TLS certificate, recipient or signing release. Enforce revocation
   and rollback constraints; unavailable freshness means stop.
5. For real network eligibility Lab requires the independently provisioned
   `distribution-approval.json`. Its canonical `CSA_DISTRIBUTION_APPROVAL`
   schema 1 includes `issuedAt`, `expiresAt`, approved `state`, exact
   `publisherKeyId`, `labKeyId`, `recipientId`, `assessmentId`, `sessionId`,
   `publisherManifestDigest`, `origin`, `tlsFingerprint`,
   `publisherLegalEntity`, `publisherKeyOwner`, `publisherPinSource`,
   `labKeyOwner`, `labPinSource`, `independentChannel`, `channelOwner`,
   `channelEvidenceDigest`, and `homeLabAcceptanceDigest`. Do not provision
   guessed values or placeholders. Independent acceptance on the exact
   signed candidate can start with a private v1 bundle and the two execution
   modes; the protected approval for a controlled HOME/LAB v2 session references
   that proof. A separate v2 live run is required before any customer approval.
   A live signature check or a healthy CI run alone cannot approve a transport.

## HOME and LAB acceptance and incident evidence

On each clean HOME and LAB Windows endpoint, use the exact same immutable
candidate and independently confirm its fingerprint. Record OS/PowerShell
version, medium integrity, active protection/policy, custody and real signer
and TLS pin verification. Exercise standard and Quick Run on equivalent
synthetic evidence, compare profile, privacy, schema and findings, and verify
online and offline signed receipts, cleanup and no persistent policy change.
Refuse missing/mismatched/revoked identity, stale policy, altered content,
wrong endpoint, replay and enforced organization policy. Run these checks
with protection active. Retain redacted results and the acceptance record
digest. Neither a HOME/LAB clean-host run nor a customer GO is recorded here.

Endpoint-security incidents and the reported portal failure remain
**NOT_EVALUATED** without primary affected-client evidence. At the affected
endpoint obtain the exact UTC time, security product and event category/ID,
detection name and action, a redacted file identifier and SHA-256, candidate
signature state, and safe portal HTTP status/correlation/stage if applicable.
Correlate Defender Operational events or Protection History separately from
SmartScreen reputation, CodeIntegrity/Smart App Control, AppLocker and
PowerShell policy. Do not share raw identities, credentials, paths, addresses
or payloads. A staging event alone is not a rejected submission; search for
the later accepted/rejected event or accepted-with-analysis-failure.

| Transport | Automated evidence | Real pilot decision |
|---|---|---|
| Legacy EXE, ZIP, launcher | Restricted assessor development only | **NO-GO** for customer delivery |
| Independently signed v1 | Shared verification and offline submission exercised with fixtures | **NO-GO** pending approved enrollment and clean HOME/LAB |
| v2 Copy, standard and process-only Quick Run | **TEST_ONLY** on Windows HTTPS; real Join **DISABLED** | **NO-GO** pending independent enrollment and live acceptance |

Use the exact commit's normal CI installer for engineering review. Use the
protected release lane and independently verified artifacts for any future
pilot; there is no approved public release tag or downloadable signed installer.
