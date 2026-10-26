# CSA 5.6.1 — vulnerability findings and administrative privileges

This is a review candidate implementing the Architect's P0/P1 reporting
corrections. Commit/push and CI installer artifacts are authorized. **Live
acceptance is pending; do not create a final release or tag for this candidate.**

## P0: concrete vulnerability findings

The generic Known Vulnerability Assessment (`CVE-001`) is an internal aggregate
control, not a CVE identifier. It remains in stored analysis, endpoint control
results, the unified report's `vulnerabilityAssessmentStatusCounts`, and the
existing risk inputs. It is excluded from client finding cards, grouped fleet
findings and remediation actions. The endpoint Console and legacy analyzer
finding lists apply the same presentation boundary.

Confirmed product/version/CVE relationships continue to create concrete
software findings. The visible finding identifiers use `SW-VULN-…`; remediation
references contain the actual CVE IDs. Actions identify the installed product
and version, expose existing vendor-listed fixed versions/advisories, and ask
for fresh collection/version verification followed by CVE re-evaluation. No
fixed version is invented when the existing source data does not supply one.
Possible and not-evaluated vulnerabilities are not promoted to confirmed
findings. Summary-only legacy evidence remains in aggregate CVE metrics without
invented product-level relationships. Applicable KEV remediation remains P1
throughout the full remediation plan.

Client finding counts and severity charts now count concrete findings rather
than also counting the summary control. Existing risk ratings, numeric scores,
applicability/source trust, rule evaluation and persisted evidence are preserved;
separate risk severity inputs retain the internal control during presentation
filtering. Framework evaluation logic is unchanged.

## P1: Administrative Privileges

The Executive Summary counts **Collector execution accounts with confirmed
administrator membership** separately from affected endpoints and elevated
Collector processes. It makes no claim to evaluate actual daily desktop users.
The effective-membership correction supersedes the original direct-SID-only
implementation; see [the decision matrix and token scope](sprint-5.6.1-effective-administrator-membership.md).

ACC-011 reconciles direct local Administrators membership with complete,
identity-bound Windows token group evidence. Domain group inheritance can
confirm membership when a group in the direct list is present in the token.
UAC-filtered deny-only SIDs remain membership evidence without granting access
or establishing an elevated process. Unresolved disagreements are PARTIAL /
SOURCE_CONFLICT; missing token evidence and a direct SID miss cannot become PASS.

Fleet identities use collected SIDs or privacy pseudonyms. Domain/Entra accounts
can span endpoints; local and unknown account scopes remain device-specific.
Legacy direct-positive proofs remain usable. Old direct-negative proofs without
token evidence are NOT_EVALUATED and require fresh collection to resolve.

## Validation and review

The targeted regressions are in `tests/test_sprint561_reporting.py`. They exercise
real ACC-011 evaluation of synthetic settings, unified/Console/legacy rendering,
mixed detailed and summary-only CVE evidence, KEV priority, preserved risk inputs,
immutable stored findings, identity deduplication and incomplete evidence.

```powershell
python -W error::ResourceWarning -m unittest tests.test_sprint561_reporting -v
python -W error::ResourceWarning -m unittest discover -s tests -q
python scripts/Generate-Sprint561-Review.py --output test-artifacts/CSA-5.6.1-Review.html
```

The updated synthetic report covers eight endpoints: direct and inherited
domain membership (one shared account), a proven standard token, token-only
membership with an unavailable direct list, a source conflict, failed token
groups, UAC-filtered local membership, and pseudonymized inherited membership.
Expected counts: **4 distinct Collector administrator accounts, 5 affected
endpoints, 6 evaluated endpoints, 2 unresolved endpoints including 1 source
conflict, and 0 elevated Collector processes**. The existing confirmed/possible
and legacy summary-only CVE cases remain in the fixture.

For live acceptance, install the **CI 5.6.1 candidate artifact**, create a new
assessment, and inspect single-endpoint and mixed-fleet reports. Confirm that
the generic control appears only as an internal summary/control result, that
actions identify product/version/actual CVEs, and that observed-user counts,
affected endpoints, unknown evidence and process elevation agree with the
reconciled ACC-011 evidence. Existing evidence may be reanalyzed without claiming
it is a fresh collection. No customer evidence is committed or published.

Original reporting correction validation (before the effective-membership follow-up): **528 Python tests and 86 PowerShell tests passed**,
with no failures or skips. The review-candidate installer build passed and is
unsigned locally. The generated review HTML and model digests match their
integrity record; all fragment links resolve and HTML anchors are unique. The
expected administrator counts are reproduced. The earlier tests asserting the
old privilege-flag fallback and old card label were updated to the ACC-011-backed
contract, while keeping their positive membership and endpoint-count assertions.

Automated Windows browser inspection was stopped by Computer Use because it
could not confidently determine the active browser URL. No further UI input was
issued. Visual layout remains a live-review check; the HTML/model checks above
are not presented as a browser acceptance result.

Compatibility declaration: CVE applicability, source trust, risk scoring/rating
inputs, session binding and transport integrity are unchanged. The follow-up
adds optional token membership evidence and allows an unknown (null) membership
flag; existing schema version and standard-user authorization gates are preserved. Product version identifiers for new collection,
analysis, reporting and installer builds are aligned to 5.6.1. Stored older
evidence retains its actual collector version. The existing public release is
unchanged pending live acceptance of this candidate.
