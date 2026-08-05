# Sprint 5.2 live acceptance

This procedure validates Assessment Intelligence and Endpoint Transparency on
two authorized Windows 11 endpoints. Run the Collector as the signed-in
standard user. Do not elevate it and do not disable Smart App Control, WDAC,
AppLocker, SmartScreen, antivirus, or the firewall to complete the test.

The `mCollector` and `mInstaller` projects were consulted only as external
technical references for the Windows Shell BitLocker property. They are not an
architectural basis for CSA, and their code, result model, installer design,
and trust assumptions are not incorporated into CSA.

## Prepare the assessment

1. Install the newest `CSA-Lab-Setup.exe` on the lab computer and verify its
   SHA-256 value against `SHA256SUMS.txt`.
2. Open CSA Lab and create one assessment for both endpoints.
3. Use the **Standard Privileges Assessment** collection mode.
4. Start collection on a Private or Domain network profile. Keep offline
   collection available if the HTTPS path is not permitted.
5. Record the assessment name and ID. Treat the resulting report as
   **Confidential - Security Assessment Data**.

## Dell mini

1. Sign in to the Dell mini as the intended standard user.
2. Open the CSA portal URL shown by CSA Lab.
3. Download and start the Collector without **Run as administrator**.
4. If Windows blocks execution, record the exact Windows Security message and
   export a CSA diagnostic bundle. Do not disable the protection control.
5. Wait for **Collection completed** and confirm that CSA Lab finishes endpoint
   analysis and CVE analysis.
6. Verify that the endpoint row uses the real Dell computer name.
7. Verify the current user and local Administrators membership.
8. Verify TPM, BitLocker status, provider, confidence, and OS volume. An
   explained `PARTIAL` or `NOT_EVALUATED` is acceptable; access denied is not a
   failure result.
9. Verify that installed software and versions are present, or that a specific
   collection limitation explains their absence.
10. Verify that CVE results are attached to exact products and installed
    versions, and that lifecycle results include a source and data version.
11. Verify the Collector version, build digest, and integrity status.

## Lenovo laptop

1. Repeat the same standard-user collection inside the existing assessment.
2. Confirm that the report uses the real Lenovo computer name and shows users,
   installed software, versions, CVE matches, and lifecycle results.
3. If Windows application control blocks the Collector, export diagnostics and
   confirm that it contains application-control state plus safe signature
   status and publisher metadata. It must contain no endpoint evidence,
   credentials, local paths, or network identities.
4. Confirm that an execution compatibility limitation is not presented as an
   endpoint security failure.

## Unified report

1. Stop collection only after both endpoint analyses have completed.
2. Generate the unified HTML report.
3. Confirm that the comparison table contains two distinct endpoint names and
   shows user, OS, risk, coverage, BitLocker, confirmed CVEs, and unsupported
   software for each endpoint.
4. Search, filter, and sort each Installed Software table.
5. Open software details and verify CVE ID, severity, CVSS, match rationale,
   affected version criteria, KEV state, source, and lifecycle data.
6. Confirm that CVE totals distinguish unique CVEs, software/CVE matches,
   affected endpoints, confirmed matches, possible matches, and KEV entries.
7. Confirm that Top Recommended Actions has no more than five deduplicated
   actions and prioritizes KEV and confirmed critical exposure.
8. Confirm the privacy notice, report metadata, and classification.
9. Confirm audit integrity is `VERIFIED` and the audit contains the Sprint 5.2
   normalization, CVE, lifecycle, BitLocker, identity, and report identity-mode
   events.

## Expected limitations

- Lifecycle results are authoritative only for exact entries in the versioned
  lifecycle pack. Rolling or vendor-dependent channels remain
  `NOT_EVALUATED` when an exact support boundary cannot be proven.
- Shell BitLocker evidence has lower confidence than the native BitLocker and
  WMI providers. Unknown Shell values never become pass or fail.
- Standard-user collection can leave privilege-sensitive evidence partial or
  not evaluated. CSA does not infer a failure from denied access.
- Real endpoint and user identities are intentionally shown in this report
  mode. Pseudonymized report selection remains future work.
- Production code-signing requires an organization-controlled Authenticode
  certificate; the build pipeline is ready but cannot establish publisher
  reputation without that certificate.
