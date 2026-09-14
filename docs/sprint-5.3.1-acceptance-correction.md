# Sprint 5.3.1 acceptance correction

Software Exposure previously reversed two meanings in the HOME report: 104
unevaluated entries appeared clean, while five products that completed their own
CVE pipeline appeared unevaluated because the assessment was PARTIAL.

`analyzer._software_results()` now selects zero-CVE results from the product's
auditable `terminalStatus == COMPLETED`, with no unresolved applicability
results. Confirmed and possible findings retain priority. An absent pipeline
cannot establish a clean result, even when the global scan says COMPLETE.

`_software_matrix()` now tracks each product instance's pipeline outcome directly.
It does not infer CVE status from risk labels. Successful zero-CVE products show
“No known vulnerabilities found”; missing, ineligible, unmapped and failed
evaluations show “Not evaluated”. Partial version evaluation and mixed completed /
unevaluated instances show “Partially evaluated”, alongside confirmed or possible
counts when present. “Product not recognized” and “CVE not evaluated” can both
describe the same entry. Existing grouping, counting and deduplication are unchanged.

The section summary uses “software product/version entries” and singular/plural
“endpoint(s)”. The empty-state logo uses a dedicated class with 72px height,
automatic width and `object-fit: contain`. Browser inspection of the running Lab
verified the 2816×1536 image renders at **132×72**, while the header retains its
36×36 containing box and `object-fit: contain`.

## Regression evidence

`tests/test_sprint531_exposure.py` supplies typed product pipeline evidence and
CVE assessments to the real analyzer. Completed and partial pipeline outcomes
are finalized by the production CVE service. The fixture does not prefill
`cveEvaluationStatus`. Accepted endpoint packages and analyzer-produced software
results pass through the actual unified report generator and HTML template.

Eight new tests cover unmapped, ineligible, provider-failed, absent-pipeline,
completed clean, confirmed, possible, unresolved-version and mixed-endpoint
results, including both endpoint orders and generated HTML. The CI report
artifact includes a synthetic Software Exposure acceptance report and JSON model:

```powershell
python -W error::ResourceWarning -m unittest tests.test_sprint531_exposure -v
python scripts/Generate-SemanticsReport.py --software-exposure --output test-artifacts/CSA-Sprint-5.3.1-Software-Exposure.html
```

Local validation: **417 Python tests passed; 62 Pester tests passed**.

## HOME baseline acceptance

The new HOME report replays the existing saved product pipelines, applicability
results, lifecycle results and source resolutions through the corrected analyzer.
It uses a separate local assessment copy. It is an **offline replay of the same
baseline**, not a new collection or a refresh against today's vulnerability data.
Original findings and evidence remain unchanged. All saved CVE details, pipeline
fields, counts, lifecycle outcomes, control findings and scores are preserved;
only the two derived product presentation fields are refreshed.

| Check | Result |
| --- | --- |
| Software product/version entries | 117 |
| Unknown/unmapped entries correctly shown as Not evaluated | 104 |
| Completed zero-CVE entries correctly shown as clean | 5 |
| Software fully evaluated | 11 of 85 eligible instances |
| Confirmed unique CVEs | 195 |
| BitLocker enabled / not enabled / not evaluated | 0 / 0 / 1 |
| Illustrator 25.2.3 CVE-2021-36009 and CVE-2021-36011 | CONFIRMED / AUTHORITATIVE_CONFIRMED, NVD and Adobe links retained |

The five clean entries are Audacity 2.4.2, IrfanView 4.58, Microsoft Edge
152.0.4191.66, XAMPP 8.2.12-0 and qBittorrent 5.2.3. “Clean” describes the completed
known-vulnerability evaluation; lifecycle status remains independent.

Local review files are under `test-artifacts/sprint531-correction/`:
`HOME-5.3.1-Correction.html`, its `.model.json`, `home-acceptance.json`, and the
offline replay script. Private HOME data is excluded from Git and CI artifacts.

This remains version **5.3.1**. The CVE applicability, source-trust and risk
engines, collector permissions, evidence schema, framework packs and metrics
arithmetic are unchanged.
