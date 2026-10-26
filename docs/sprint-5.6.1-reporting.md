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

The Executive Summary displays **distinct observed interactive administrator
users** and **affected endpoints** separately, with endpoint links. Membership
comes from existing ACC-011 PASS/FAIL evidence containing current-user SID
correlation with the collected local Administrators list. Display names alone,
a process privilege flag, unresolved membership, incomplete collection,
contradictory identities or missing ACC-011 evidence do not establish membership.
Those endpoints remain NOT_EVALUATED, and partial fleet coverage is explicit.

Fleet identities are deduplicated by SID or the existing privacy-mode SID
pseudonym. Domain/Entra identities can span endpoints. Known local identities
remain device-scoped, including cloned-machine SIDs. This counts the execution
users observed in the latest accepted endpoint evidence, not every logged-on
user or all sessions. The collection implementation and privacy policy are not
expanded.

Collector process elevation is reported independently using a boolean
`privilegeContext.isElevated` observation. Membership never proves elevation;
absence of process evidence remains NOT_EVALUATED. Other processes and sessions
are explicitly outside this observation's scope.

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

The synthetic review report contains two endpoints sharing one observed domain
administrator identity and one endpoint with unavailable membership evidence.
The two detailed software results share two confirmed CVEs (one KEV) and one
possible CVE; a third endpoint contributes a legacy summary-only confirmed CVE.
Expected executive counts: one distinct observed administrator, two affected
endpoints, one NOT_EVALUATED endpoint, and zero elevated Collector processes.

For live acceptance, install the **CI 5.6.1 candidate artifact**, create a new
assessment, and inspect single-endpoint and mixed-fleet reports. Confirm that
the generic control appears only as an internal summary/control result, that
actions identify product/version/actual CVEs, and that observed-user counts,
affected endpoints, unknown evidence and process elevation agree with the
existing ACC-011 evidence. Existing evidence may be reanalyzed without claiming
it is a fresh collection. No customer evidence is committed or published.

Local validation on 2026-10-26: **528 Python tests and 86 PowerShell tests passed**,
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
inputs, evidence schemas, collection semantics, session binding and transport
integrity are unchanged. Product version identifiers for new collection,
analysis, reporting and installer builds are aligned to 5.6.1. Stored older
evidence retains its actual collector version. The existing public release is
unchanged pending live acceptance of this candidate.
