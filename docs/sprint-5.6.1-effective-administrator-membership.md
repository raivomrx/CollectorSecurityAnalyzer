# CSA 5.6.1 — ACC-011 effective administrator membership correction

Review candidate; Architect acceptance and live Windows testing remain pending.
No release/tag is created by delivering this correction.

## Observed defect and scope

A direct user-SID miss in local Administrators previously became ACC-011 PASS.
That is insufficient when a domain group grants membership. The shared
PowerShell engine now reads its own execution token using GetTokenInformation,
and the rule/report share a single resolver. Both EXE and script transport use
this engine. No account/group changes, impersonation, linked-token access,
privilege adjustment, process elevation or domain-directory enumeration occurs.

This observes the **Collector execution account**. It does not establish who
normally uses the desktop or assess every logged-on user. LOGGED_ON_USERS no
longer echoes the execution account as a proven desktop user: it explicitly
records DESKTOP_USERS_NOT_EVALUATED. Existing profile inventory remains separate.

## Evidence and decisions

New optional Accounts setting `EXECUTION_TOKEN_ADMIN_MEMBERSHIP` records:
provider/status, subject SID, complete-query flag, builtin Administrators SID,
SID attributes, elevation type, and only the intersection of token groups with
groups already collected from local Administrators. It does not export the full
token group list or any token/handle. Subject/group SIDs use the existing privacy
mode. Process elevation and integrity remain separately measured.

| Direct list / token evidence | ACC-011 / account membership |
| --- | --- |
| User SID matches; token agrees or unavailable | FAIL / DIRECT |
| User SID absent; listed domain group matches token; Administrators SID enabled or deny-only | FAIL / INHERITED_DOMAIN_GROUP |
| Direct list unavailable; token confirms enabled or deny-only Administrators SID | FAIL / TOKEN_BASED |
| Complete token query has no Administrators SID; no contradictory direct match | PASS / STANDARD_USER_TOKEN |
| Direct user or inherited group assignment matches, but token Administrators SID is absent | PARTIAL / SOURCE_CONFLICT |
| Direct miss and token administrator SID present without a proven listed-group path | PARTIAL / SOURCE_CONFLICT |
| Direct miss; token groups missing, failed, incomplete or from whoami fallback | NOT_EVALUATED |
| Present but disabled SID without direct proof | PARTIAL / unresolved |
| Mismatched token subject, malformed attributes or duplicate sources | PARTIAL / SOURCE_CONFLICT |

Enabled (0x4) and deny-only (0x10) are distinct and cannot both be set.
A deny-only SID cannot grant access. Only a LIMITED elevation type is labelled
UAC_FILTERED_DENY_ONLY; other deny-only tokens remain DENY_ONLY. Neither implies
that the Collector process is elevated. Read-only API details:
[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation),
[TOKEN_GROUPS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups),
[SID attributes](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token).

If native querying fails, whoami may supply only the existing process-integrity
authorization gate, with exit-status validation. It cannot supply administrator
membership. An unavailable query leaves membership null rather than false.
`STANDARD_USER` remains a process authorization mode; it is not sufficient
membership evidence. Elevated/SYSTEM processes and unknown integrity still fail
the existing standard-user gate.

## Compatibility and review

The evidence manifest adds an optional setting without expanding the mandatory
collection-profile denominator. Schema 2.0 remains in use; the membership flag
accepts boolean or null for an unknown observation. Legacy direct-positive
ACC-011 proofs remain useful; legacy direct-negative proofs without token groups
remain NOT_EVALUATED. Reanalysis cannot invent token data that was not collected.
Domain/Entra accounts deduplicate by SID/pseudonym; local/unknown identities are
scoped to each endpoint. All counts exclude unresolved observations explicitly.

CVE-001 customer-view filtering, concrete software/CVE findings, applicability,
source trust, KEV priority, risk weights/scoring logic, BitLocker, authentication,
TLS/session binding, integrity and privacy policies remain unchanged. ACC-011
outcomes and resulting risk inputs change only where corrected evidence warrants
it. No raw customer evidence, credentials or secrets are part of this change.

## Automated and live acceptance

Python regressions exercise the matrix, nested group token intersections,
UAC/restricted deny-only distinctions, failed queries, identity mismatch,
duplicate evidence, stored/raw proof conflict, privacy pseudonyms, local scoping,
fleet deduplication and independent process elevation. Pester runs the actual
own-token reader on Windows and mocks blocked/unavailable providers, enabled,
deny-only, absent and disabled SIDs; it checks privacy and desktop-user scope.

Generate the updated eight-endpoint synthetic review with:

```powershell
python scripts/Generate-Sprint561-Review.py --output test-artifacts/CSA-5.6.1-Review.html
```

Expected: 4 distinct Collector administrator accounts, 5 affected endpoints,
6 evaluated, 2 unresolved (1 source conflict), 0 elevated Collector processes.
Existing CVE cases still produce 3 unique confirmed and 1 possible CVE.

HOME/WORKGROUP live testing must check fresh collection, actual process context,
report wording and existing CVE remediation. It cannot establish domain live
acceptance. Domain automation covers the defect, but a fresh domain endpoint
with inherited administrator membership should be reviewed when available.
Do not approve P1 solely because a workgroup endpoint passes.

## Local validation — 2026-10-26

- Full Python suite: **543 passed**, 0 failures, 0 skips, with
  `-W error::ResourceWarning`. Negative provider tests intentionally log simulated
  errors/warnings; these are not failed or real upstream collection results.
- Windows PowerShell 5.1 / Pester 5.7.1: **96 passed**, 0 failures/skips, including
  actual own-token integration and the existing transient-file-lock regression.
- Updated eight-endpoint HTML/model integrity hashes, unique anchors and every
  internal fragment link verified. Counts reconcile with the matrix above.
- Collector, PyInstaller Lab and NSIS installer builds passed. The new resolver
  is present in the packaged Python archive. Expected optional/platform-specific
  PyInstaller missing-module notices remain; no application dependency failure
  was observed. Signing material is unavailable locally: installer is NotSigned.
- Packaged Lab started without a browser against a new isolated empty data root;
  localhost HTML/version and assessment API checks passed, then the test process
  was stopped. This is a startup/API smoke test, not visual or live acceptance.
- Product/Collector/report/installer versions remain 5.6.1. The CI-built artifact
  and exact source commit must be verified after push; no public release/tag is
  created. No customer evidence or secrets are included in the committed files.
