# CSA 5.6.2 — Correction A Final REP-1 Boundary Fix

Status: **review candidate, release HOLD**. No public release/tag or
production-client deployment before architecture acceptance. The correction keeps
version 5.6.2; its commit identifies the new installer candidate.

## Before and after

The previous contract allowed `0 == 0` to establish COMPLETE and 100% coverage.
It also accepted equal nonzero counters when `scanCompleted` was false. CVE-001
could report a clean PASS from an empty scan or incomplete software collection.

The shared status contract now requires successful software collection, an
explicit boolean `scanCompleted=true`, a positive number of evaluated eligible
products, matching eligible/evaluated counts and no unresolved eligible-product
or CVE evaluation. Provider health remains independent.

| Collection / evaluation evidence | Assessment | Coverage / CVE-001 |
|---|---|---|
| Successful inventory, zero eligible | NOT_EVALUATED, EMPTY scope, NO_ELIGIBLE_PRODUCTS | 0%, no clean PASS |
| One eligible and evaluated, scan not completed or completion unknown | PARTIAL, SCAN_NOT_COMPLETED | No full assessment percentage; no clean PASS |
| One eligible and evaluated, successfully completed scan | COMPLETE | 100%; PASS only if no confirmed/possible/unresolved vulnerability |
| Two eligible, one evaluated, provider SUCCESS | PARTIAL | 50%; provider remains SUCCESS |
| Failed inventory | NOT_EVALUATED | No clean PASS; confirmed findings retain their failure and risk |
| Partial inventory | PARTIAL when some evaluation exists | No clean PASS or full assessment percentage |
| Counts match but an eligible stage/CVE evaluation is unresolved | PARTIAL | No full assessment percentage or clean PASS |

## Components and compatibility

- `cve/status.py` centralizes the boundary decision, reason and scope metadata.
  Contract version is **1.1**. `coverageComplete` is an assessment conclusion;
  counters remain available independently. If counters imply 100% but scan,
  collection or unresolved evidence cannot establish completeness, the analysis
  metadata uses `coveragePercent: null`, displayed as **Not established**.
  Empty scope has `coveragePercent: 0.0`. This avoids inventing 99% or erasing
  successfully evaluated product counts.
- The CVE service's empty summary no longer has complete coverage. Its raw
  `scan_complete` still records that iteration finished, which does not establish
  a nonempty successful assessment by itself.
- Analyzer, CVE-001, pipeline audit metrics, endpoint HTML and unified reports use
  the same contract. The rule's existing confirmed/possible/KEV branches and risk
  scores are retained; only the unqualified clean-PASS gate changes.
- Unified endpoint details show assessment status, scope reason and honest
  coverage. Empty endpoint/fleet software-evaluation ratios do not default to
  100%. Fleet aggregation also refuses COMPLETE when its instance scope is empty.
- Older analysis without explicit scan-completion evidence remains readable but
  cannot establish COMPLETE by its label alone. Reanalysis establishes the new
  evidence. New nullable analysis coverage is distinct from Collector capability
  coverage and provider health.

Collector evidence schemas, CVE applicability/product identity, security risk
weights, privacy processing and all Collector distribution/session/TLS/security
controls are unchanged. No real endpoint or customer collection is required for
this correction; all acceptance data is synthetic.

## Regressions and review artifacts

`tests/test_cve_status_boundaries.py` covers all requested boundaries, explicit
scope/reasons, unfinished 1/1 counters, unresolved stages, report scope, provider
health independence and preservation of confirmed failure/risk. The original
implementation failed the new regressions before the correction.

`tests/test_audit_correction_a.py` adds accepted-package pipeline/Lab/report and
compliance evidence checks for empty and unfinished scans. A deterministic fake
provider executes the real scan; the unfinished fixture changes only the scan's
completion flag, never injects COMPLETE. Empty/incomplete CVE-001 yields MISSING
compliance evidence instead of support or contradiction for a clean-PASS requirement.
Existing positive legacy test fixtures now supply explicit scan-completion proof.

`scripts/Generate-AuditCorrectionReport.py` generates the updated five-endpoint
review report (complete, partial, failed collection, empty, unfinished). It verifies
the HTML/model sidecar independently and checks the boundary states and identifiers.
The report workflow uploads only synthetic HTML/model/sidecar artifacts.

```powershell
python -W error::ResourceWarning -m unittest tests.test_cve_status_boundaries tests.test_cve_engine tests.test_audit_correction_a tests.test_sprint521_reporting tests.test_lab_sprint51.UnifiedReportTests tests.test_html_report tests.test_compliance_engine -q
python -W error::ResourceWarning -m unittest discover -s tests -q
powershell.exe -NoProfile -File scripts/Invoke-CollectorTests.ps1
python scripts/Generate-AuditCorrectionReport.py --output test-artifacts/CSA-REP1-Boundary.html
```

Exact final test counts, CI/installer URLs, source commit, SHA-256 and signature
status are recorded in the delivery handoff. Next step is architecture acceptance
of these boundaries and the synthetic report; the earlier COL-1 design remains
separate and unimplemented. Release HOLD remains in force.
