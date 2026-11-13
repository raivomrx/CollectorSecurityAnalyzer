# 5.6.8.3 P0 live correction — delivery version 5.6.8.4

Baseline: 5.6.8.3, commit `3785616`. Public release: **HOLD**.
5.7 remains postponed. Engineering verification is not project-manager
HOME/LAB acceptance. Use the exact installer artifact/commit in the handoff;
the public 5.6.0 release is not this correction.

## Root cause and missed test

The old customer renderer displayed its fallback when there was no usable
pilot cookie, no independently verified and authorized launch matching the
request source, no enrolled production advertisement, and no explicit development
distribution. Valid Join authorization alone did not prepare those methods.

`start_collection` started HTTPS and the temporary scoped firewall lifecycle,
but did not create the launch authority that Join needed. The old tests called
issue, verify, authorize and code activation before opening Join. Consequently,
they passed without exercising the actual new-assessment/Start-only journey.
The old EXE-labelled delivery was also a ZIP/CMD starter, contrary to acceptance.

The supplied screenshot is consistent with this exact fallback. The installed
local Lab was the November 12 candidate, and no active local Lab process or
November 13 assessment was available for inspection. Thus the particular remote
HOME/LAB authorization row cannot be reconstructed from this workstation.
We do not invent a runtime record or claim to have inspected that remote session.

A separate failure found in actual local frozen-app testing was a managed Python
runtime SSL CA-policy data file missing from the bundle. The spec now includes
that resource if the build runtime needs it. Its verification is preserved.
Official CI Python does not require that conditional resource.

## Operator flow

1. Install the independently obtained and fingerprint-checked **5.6.8.4** Lab
   candidate from the exact GitHub Actions build. An unsigned pilot installer
   and its checksum do not establish production Publisher authenticity.
2. Create a **new assessment** with the intended profile, direct LAN interface,
   bounded source subnet, endpoint count and expiry. Existing customer-use
   authorization remains a prerequisite; it is not requested again.
3. Press **Start Collector**. This is the local assessor's auditable approval
   for the selected assessment scope and private pilot. No additional per-client
   code, MachineGuid collection, risk form, command parameters or trust setup
   is needed. The Distribution status in Lab shows readiness or an actionable
   preparation diagnostic. Do not give the customer an old assessment URL.
4. Provide the Join URL through the assessor's approved direct interaction.
   The page has the approved two-option layout:
   - **PowerShell Quick Run — Recommended**: Copy Quick Run, paste once into
     ordinary PowerShell or CMD, press Enter. No code/password prompt.
   - **Windows EXE Collector**: download `CSA-Collector.exe`, run normally.
     It is one executable, with no installer, manual extraction or CMD starter.
5. Observe accepted evidence and processing in Lab. Stop collection and generate
   the HTML report through the existing CVE completeness gates. Transport tests
   explicitly acknowledge missing CVE analysis; they never assert it completed.

The Join browser is not an independent trust authority. The private pilot's
independent origin is the assessor's previously verified local Lab installation
and approved delivery interaction. A command/hash from an arbitrary unverified
page cannot establish that origin. Start does not turn a self-supplied checksum
or private ephemeral signing certificate into production trust.

## Implementation and security boundary

The project lead's November 13 Start-only instruction replaces manual per-client
preparation for this private workflow. This completes ADR 5682 delivery using
the same native verifier, detached CMS release/session signatures, private
assessor assurance and receipt pipeline; it adds no production signing protocol.
The installed Lab's exact Collector/template build is checked before Start and
before issuance. Start audit records actual scope, time and authorization ID.
It does not fabricate a customer contract reference or human acceptance result.

For each authorized Join source, Lab prepares a bounded one-use grant and seals
the existing immutable native Collector plus its existing signed session bundle
inside a directly executable private container. Compile-time pins bind the
captured package, approval and inner executable. The native Collector repeats
the existing complete signature/manifest/profile/privacy/session checks before
running the shared engine. No signed PE is modified by appending session data.

Quick Run requests process-only `ExecutionPolicy Bypass`, pins Lab TLS and the
exact final EXE, rejects redirects/oversized/truncated downloads, holds a read
lease through execution and invokes the same container with `--quick-run`.
Neither path uses IEX/DownloadString, enrolls a root certificate, changes a
persistent execution policy, elevates Collector, installs an agent or disables
Defender/AMSI/WDAC/AppLocker. GPO/application-control refusal remains effective.
Only narrowly classified Windows sharing/lock errors get bounded retry.
Trust/digest/path/signature failures never count as successful verification.

**Binding is explicit:** automatic grants use the actual HTTP source address
and the client's direct route to the signed Lab origin. They are session,
profile, source and time scoped, not hardware-attested MachineGuid identities.
The existing manually prepared hardware-bound mode is retained separately.
The server checks source again at nonce redemption. NAT/proxy routes and source
mismatch fail closed. DHCP/source reassignment is a limitation of this LAN-bound
pilot; use a controlled assessment network and short session. Do not describe
an IP address or a client-reported execution mode as device/policy attestation.

Download attempts and total invitations are bounded. The grant is one use;
expired, paused, stopped, revoked or changed deliveries are refused. Revoking
a source cannot be undone by refreshing Join under the same Start approval.
Pause and an explicit new Start approval are needed to reauthorize it.
Sensitive package/session material on Lab is retired after receipt/expiry or
revocation. Temporary client extraction is removed after success/failure.
Delete the browser-downloaded private EXE after the run. No reusable credentials
are placed in the copied command. Production release remains HOLD.

Collection/evidence schemas, privacy enforcement, assessment rules, CVE logic,
report semantics and protection settings are unchanged. Assurance remains
`ASSESSOR_VERIFIED_PILOT`; production Authenticode is **not established**.

## Tests and remaining acceptance

`test_start_only_delivery` starts from a new assessment and calls no handoff,
authorization or activation API. It exercises the real native EXE with no flags
and actual generated PowerShell/CMD commands, equivalent synthetic acquisition
through real privacy/receipt/report processing, wrong source, route mismatch,
replay, expiry, pause, revocation, missing installed files, changed container,
wrong TLS/digest and absence of Start authority. Hosted elevated CI must honor
the real standard-user refusal; that refusal is not successful collection.

`scripts/Test-PackagedCustomerJourney.py` runs the built/installed Lab executable
through its actual local API, creates a new assessment and presses only Start.
It checks actual Join/Copy in headless Edge, downloads a real PE and optionally
executes all three shell variants with the unmodified installed Collector.
`--execute` on a standard-user workstation stores real evidence privately under
the chosen short output directory (the .NET Framework tools have Windows path
limits). Do not upload that directory. CI's hosted token
test cannot replace a real standard-user endpoint run.

The final handoff records actual executed counts, exact CI commit/installer,
signature/hash, packaged outcomes and a sanitized screenshot. Raw customer/host
evidence, session keys, private packages and logs are excluded from Git.

**Still required from the project manager:** fresh HOME and LAB endpoints,
the exact installed candidate, a new assessment, ordinary-user EXE and one-paste
Quick Run, protection controls active, accepted/processed evidence, valid signed
receipts, equivalent profile/privacy and the HTML report. Record Windows policy
or detection refusals honestly. Do not disable protections to pass acceptance.
Only the project manager's confirmation completes the sprint definition of done.
