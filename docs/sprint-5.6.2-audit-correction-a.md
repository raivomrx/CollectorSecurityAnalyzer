# CSA 5.6.2 — Independent Audit Correction A

Release status: **HOLD**. Source and CI installer are review candidates only.
No public release/tag or production-client deployment is authorized before
architecture acceptance. Version remains 5.6.2; the source commit identifies this
correction. Use a fresh assessment/package after the accepted update; previously
downloaded packages and existing raw evidence cannot be retroactively redacted.

## Finding-to-fix handoff

| Finding | Previous behavior | Correction and validation |
|---|---|---|
| REP-1 | Provider SUCCESS was exported as assessment status; successful requests could conceal incomplete evaluation. | `cve/status.py` derives COMPLETE from explicit successful software collection and reconciled eligible/evaluated counts. Analyzer exports separate `providerStatus`/provider health and `assessmentStatus`; pipeline, Lab dashboard/background state, Console endpoint report and unified report consume the contract. Successful provider + unmapped eligible product is PARTIAL; failed/unknown collection is NOT_EVALUATED. No eligible products has an explicit scope statement. Fake-provider E2E runs actual accepted-package analysis/retry without inserting COMPLETE. |
| PRV-1 | Standard collection could claim privacy mode while exporting identifiers, including duplicate module metadata. | Shared `Privacy.psm1` applies the profile to the complete in-memory evidence document before its first write, including configured/effective values, module copies, diagnostics and software paths. Both transports use that engine. Assessment-scoped HMAC pseudonyms preserve principal SID/token/group correlations, device deduplication and same-domain-account fleet deduplication. Metadata records `PROFILE_ENFORCED`, effective policy and scope. Denied software inventory is empty and NOT_EVALUATED with an explicit capability limitation. Tests exercise the production serialization tail, inherited ACC-011, same/different assessment contexts, profile controls and leakage into generated HTML/model/log output. |
| REP-2 | Report fields unconditionally said VERIFIED/YES. | Recheck recorded archive payload hashes/sizes/binding, recorded transport digest, pinned-certificate receipt signature, normalized evidence binding and session build allowlist. Each field reports the corresponding result; missing artifacts are NOT_EVALUATED and failed checks NOT_VERIFIED. A report cannot independently authenticate itself: its own integrity is NOT_EVALUATED, with instructions for checking the separate sidecar. Tests mutate/delete source artifacts and independently recompute generated HTML/model digests. |
| REP-3 | Missing or unreadable prerequisite could produce PASS. | REMOTE-001, REMOTE-002 and UPD-002 require one successful typed prerequisite. Missing, failed, partial, duplicate or unreadable gates produce NOT_EVALUATED; confirmed inactive gates produce NOT_APPLICABLE with zero risk score. Regressions exercise each rule and adverse prerequisite state. |
| BL-1 | Unknown/error finding statuses contradicted STATUS_IS PASS with high confidence. | Unavailable findings produce missing or inconclusive evidence with zero decision confidence. Tests iterate every STATUS_IS requirement in every bundled compliance framework, check both evidence and resulting control assessment, and preserve confirmed FAIL contradiction/confidence. |
| COL-1 | Self-supplied digests could be mistaken for independent authenticity. | Independently reproduced the unsigned EXE consistency limitation with a harmless module/manifest/archive rewrite and the production verifier. No runtime trust change. See the separate [investigation/design proposal](COL-1-trust-anchor-design.md). Report build trust is explicitly scoped to the recorded session allowlist. |

## Privacy scope and operational limits

The random 256-bit assessment pseudonym key is stored under the existing restricted
assessment keys directory. It is included only in the trusted, short-lived session
package, passed in memory to collection and cleared from the HMAC working state.
It is not evidence, a log field or report content. Authorized encrypted assessment
backups retain assessment state, including keys. Downloaded session packages must
be handled as confidential material, as they already contain enrollment credentials.
Sharing the assessment key with participating endpoints permits correlation inside
that assessment; pseudonyms are not anonymization against a holder of that key.

User/service/principal names, machine/domain/network labels, tenant/device IDs,
non-well-known SIDs and certificate subjects follow the effective policy. Public
Windows well-known group/service/integrity SIDs remain to preserve meaning; domain
and local account SIDs are pseudonymized. Public software names, publishers,
versions and security state values remain intact for identity and applicability.
User-profile paths are redacted; raw registry dump fields and diagnostic free text
are withheld by default. Safe status/error/provider codes remain available.

Strict standalone mode can tighten profile controls; it cannot loosen them. A
standalone invocation without a session privacy context gets collection-scoped
pseudonyms and truthfully records COLLECTION scope. Invalid context/policy fails
before evidence is returned. Standard-user collection permissions, no-elevation
behavior, schema version 2.0/5.0, TLS/session/replay/receipt checks, offline encryption,
CVE product identity/applicability and security risk weights remain unchanged.
The administrator SID parser additionally accepts the new 24-hex pseudonym form
while retaining legacy 12-hex identifiers. Older evidence remains readable, but a
legacy SUCCESS label without sufficient collection/coverage evidence is not COMPLETE.

## Repeatable validation

```powershell
python -W error::ResourceWarning -m unittest discover -s tests -q
powershell.exe -NoProfile -File scripts/Invoke-CollectorTests.ps1
pwsh.exe -NoProfile -File scripts/Invoke-CollectorTests.ps1
python scripts/Generate-AuditCorrectionReport.py --output test-artifacts/CSA-Audit-Correction-A.html
```

Original-defect regressions were run before corrections: CVE completion, conditional
gates, all STATUS_IS mappings, report integrity assertions and privacy serialization
failed as expected. The corrected suites and synthetic E2E are required in delivery.
The synthetic artifact includes real pipeline-derived COMPLETE/PARTIAL/NOT_EVALUATED
states with provider SUCCESS, inherited administrator membership, fleet account
deduplication, privacy-safe evidence and independently checked integrity sidecar.
CI uploads only that synthetic report/model/sidecar; no session keys or raw evidence.

The final delivery handoff records exact test counts, source commit, CI run/artifact,
installer SHA-256 and signing status. A locally built installer is smoke-tested
against isolated empty Lab data; it is not installed over the live client.

Local validation: 572 Python tests passed; Windows PowerShell 5.1 and PowerShell 7
each passed 110 Pester tests with zero skips/failures. All four bundled framework
packs passed strict source validation. The active/reviewed release gate has no
ACTIVE packs and therefore performs no pack checks; that is not a claim that
draft mappings have been accepted for release. The synthetic report/sidecar and
packaged HTML/API startup checks passed. Expected missing signing credentials
produce unsigned candidates, reported explicitly in the final handoff.

## Architecture acceptance still required

- Review all five mandatory corrections and the synthetic audit report.
- Review COL-1 separately and approve an initial publisher/Lab trust provisioning
  design before any security-sensitive implementation.
- After acceptance, run authorized HOME/enterprise live collection and verify
  profile redaction, inherited/local administrator correlation, fleet counting,
  partial/unknown CVE states and report sidecar verification on a fresh assessment.
- Production signing and real endpoint-protection acceptance remain separate
  checks; local/CI synthetic tests do not establish that they have passed.

No real customer evidence, endpoint identifiers, credentials or session packages
are part of the committed change or synthetic CI artifacts.
