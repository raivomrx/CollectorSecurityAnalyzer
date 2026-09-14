# Sprint 5.3.1 — Report semantics and client clarity

Release target: **CSA Lab / report / Collector 5.3.1**. The collector capability
contract, evidence manifest and assessment evidence schema versions are unchanged.

## BitLocker: evidence to conclusion

The September HOME assessment did **not** contain a confirmed disabled state:
`diskEncryption.settings` was empty. The accepted collector evidence recorded
access-denied native/WMI queries and a failed manage-bde query. No fallback
returned usable system-volume evidence. Its old `0 / 1 enabled` card was a count
of confirmed protection, not proof of one disabled endpoint.

Separately, the report and BIT-001 used independent interpretation paths. The
report exposed control statuses (`PASS` / `FAIL`) as posture labels, and BIT-001
used Python truthiness for successful evidence. This could turn null/invalid
values into FAIL or nonempty strings into PASS. The legacy adapter and native/WMI
collector also contained unsafe false-like coercions.

`evidence.bitlocker.resolve_bitlocker` now defines the shared conclusion:

| Reliable system-volume evidence | Semantic state | BIT-001 result | Client label |
| --- | --- | --- | --- |
| SUCCESS + boolean true | ENABLED | PASS | ENABLED |
| SUCCESS + boolean false | NOT_ENABLED | FAIL | NOT ENABLED |
| Missing, invalid, partial, denied or unavailable | NOT_EVALUATED | NOT_EVALUATED | NOT EVALUATED |
| Explicit FAILED collection | ERROR | ERROR | ERROR |

An explicitly different volume type cannot establish OS-volume protection.
Configured policy intent is not effective protection. Partial evidence remains
conservative because it does not certify a reliable completed protection check.
The collector preserves unknown values as null, checks WMI method return values,
and no longer casts unknown protection metadata to false. It adds no providers,
elevation, privileges, network access, security changes or new capabilities.

Normalization stores the additive `diskEncryption.bitLocker` conclusion beside
the unchanged raw settings. BIT-001 uses the same resolver on parsed evidence.
Reporting uses that resolver on stored settings too, allowing old assessments to
be rendered correctly without mutating their evidence or trusting stale derived
state. Report `bitLocker.status` retains control-result vocabulary; `state`,
`displayLabel`, `collectionStatus` and `reason` make its meaning explicit.

Overview, Details, collected-system information and executive aggregation share
this conclusion. A confirmed disabled endpoint still produces exactly one
actionable BIT-001 failure, with the existing severity and score. Summary metrics
now count enabled, not enabled, not evaluated and error separately. They never
derive disabled as total minus enabled. The fixture gives **1 enabled / 3**, with
**1 not enabled and 1 not evaluated**. The 10-endpoint regression gives 6 / 2 / 2.

The existing HOME evidence therefore correctly remains **0 enabled / 1**,
**0 not enabled, 1 not evaluated**. A fresh HOME collection may resolve the state
if a provider returns usable evidence; the application must never promise that
standard-user access can always determine it.

## Vulnerability evaluation terminology

Before: `CVE coverage: 12.9%`.

After: **Software fully evaluated for known vulnerabilities: 11 of 85 eligible
software instances (12.9%)**.

The executive primary result is **Confirmed vulnerabilities: 195**. Software
evaluation is a separate scope metric with the ratio prominent and the percentage
secondary. A visible, keyboard-focusable explanation immediately below the cards
states that it is not the percentage of all CVEs discovered. It also states that
the 74 eligible instances not fully evaluated are an assessment limitation and
are not implicitly vulnerable. Metric links use `aria-describedby` and lead to
that explanation, so the meaning is available without hover. The same wording is
used in Vulnerability Exposure, scope details and limitations. Legacy endpoint
HTML explicitly labels its separate provider-stage evaluation ratio rather than
calling intermediate provider results fully evaluated instances. The explanation
is ordinary printable text. Core assessment coverage,
framework coverage and enrichment coverage retain their separate meanings.

The additive `softwareVulnerabilityEvaluation` object names the counting unit,
eligible / fully evaluated / not fully evaluated counts, percent, ratio and
explanations. It is also available inside `cve`. Existing `coveragePercent`,
`coverage.cveCoverage`, `eligibleCveCoveragePercent` and other JSON keys remain
compatible. Their arithmetic and CVE-engine meaning are unchanged. In particular,
`softwareIntelligence.coveragePercent` still divides by all discovered instances;
the client ratio uses **eligible** instances. The raw CVE summary's intermediate
evaluated-product count is not substituted for end-to-end completed instances.

## Regression boundaries

```text
CVE applicability engine changed: NO
Source-trust engine changed: NO
Risk engine changed: NO
Collector privilege/security model changed: NO
Assessment evidence schema breaking change: NO
```

The only risk-explanation edit renames a scope modifier in prose. Critical-risk
triggers, CVSS, CPE resolution, platform logic, source trust, fixed versions,
deduplication and software mapping behavior remain unchanged. Framework packs and
their pinned digests remain unchanged; an existing E-ITS source-mapping caveat
about CVE data availability is unrelated to the renamed percentage metric.
Existing Illustrator 2021 **25.2.3** regressions verify **CVE-2021-36009** and
**CVE-2021-36011**, `CONFIRMED`, `AUTHORITATIVE_CONFIRMED`, NVD and Adobe advisory
links. The regenerated HOME report preserves both relationships and its total
195 confirmed CVEs.

## Validation and artifacts

Local results: **409 Python tests passed**, **62 Pester tests passed**, and
**4 framework packs validated**. After final wording and per-endpoint assertion
refinements, the **9 semantic/HTML tests** and framework validation passed again.
The Sprint 5.3.1 Python module contains 7 tests, including parameterized state
cases; Pester adds 3 tests to the prior 59.

Run all Python tests with ResourceWarning treated as an error:

```powershell
python -W error::ResourceWarning -m unittest discover -s tests -p "test_*.py" -q
./scripts/Invoke-CollectorTests.ps1 -ResultPath test-artifacts/pester-results.xml
python -m frameworks.cli validate --all --strict-sources
python scripts/Generate-SemanticsReport.py --output test-artifacts/CSA-Sprint-5.3.1-Semantics.html
./scripts/Build-CSALab.ps1
```

The new Python suite covers typed positive/negative evidence, malformed and missing
values, unavailable/partial/error results, legacy conversion, mixed aggregation,
195 confirmed CVEs independently of 11/85 evaluated instances, and full package
acceptance → normalization → control findings → Overview/Details HTML. Pester adds
disabled JSON round-trip, unknown-native-state and denied-primary/disabled-fallback
cases. CI generates the mixed-fleet HTML and model as inspectable artifacts.

Local deliverables are under `test-artifacts/sprint531/` and `dist/installer/`.
Real HOME evidence and reports are local only and excluded from Git. HOME was
re-rendered from a work copy of its existing accepted evidence; this is **not** a
fresh endpoint collection or live acceptance of the new installer.

Desktop/mobile and print visual inspection remains a manual acceptance item:
the browser security policy rejected opening the local HTML during this run.
Automated content/HTML contracts and unchanged theme, responsive, search and print
CSS/JavaScript are checked, but do not substitute for rendered visual inspection.

## HOME live acceptance

1. Install the 5.3.1 `CSA-Lab-Setup.exe` from the verified build artifact. If the
   artifact is unsigned, retain the existing application-control policy; use the
   organization's trusted distribution path rather than disabling protection.
2. Create a fresh assessment and run its Collector on HOME as the standard user.
3. With reliable `SUCCESS / false` OS-volume evidence, confirm Overview and
   Details show **NOT ENABLED**, one BIT-001 FAIL exists, and the enabled card is
   **0 / 1**, with **1 not enabled / 0 not evaluated**.
4. If evidence remains unavailable, verify **NOT EVALUATED**, **0 not enabled /
   1 not evaluated**, and retain the actual provider limitations for review.
5. Check confirmed CVEs separately from the eligible-software ratio. The baseline
   evidence is **195 confirmed CVEs**, **11 of 85**, **12.9%**, **74 not fully
   evaluated**; fresh data may legitimately differ.
6. Inspect Illustrator 25.2.3's two named confirmed CVEs and advisory links.
7. Review the mixed demo in System/Light/Dark at wide desktop and mobile widths;
   check failure/unknown labels, card balance, full-width CVE details, Software
   Exposure cards, search, contents, expand/collapse and keyboard explanation.
8. Print/save to PDF and verify that the software-evaluation explanation and the
   distinct BitLocker labels remain readable. Check short join codes and both
   copy controls during the fresh collection workflow.
