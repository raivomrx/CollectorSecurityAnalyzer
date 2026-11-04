# CSA 5.6.6 · Audit2 correction A

**Release: HOLD pending broader security remediations and live HOME/LAB retesting.**

| Audit finding | Correction | Regression |
| --- | --- | --- |
| N-7 | Collector JSON readers decode strict UTF-8, accept an optional UTF-8 BOM and stop on malformed evidence before package creation. The verified JSON object is used for packaging. | `ConsoleCollector.Tests.ps1`, EXE and PowerShell `test_collector_launcher.py` |
| CVE-12 | Verified CPython Windows release titles and publisher corroborate MSI version decoding. Keep the raw version, interpreted version, source and conflict reason. | `test_verified_python_msi_and_title_agreement`, frozen HOME/LAB comparison |
| CVE-1 | Applicability uses typed comparisons. Numeric build variants at the same boundary, unknown schemes and contradictory range bounds stay unresolved. Explicit CNA SemVer and verified CPython/OpenSSL release schemes preserve prerelease and patch ordering. | `test_version_schemes_and_nonzero_build_boundary`, `test_cna_semver_scope_and_explicit_default` |
| CVE-2, CVE-4, CVE-5 | Recognize positive OS and product architecture evidence, separate unknown from confirmed disjointness, and preserve the version and source limitations in the analysis. A host architecture alone cannot establish application architecture. Empty queries without installed catalogue evidence remain partial with `NO_CVE_ROWS`. | `test_nvd_product_architecture_and_platform_need_positive_evidence`, `test_uncatalogued_version_uses_family_range_query`, `test_frozen_nvd_cna_evidence_to_unified_report` |
| REP-1 boundary | Provider SUCCESS remains independent of completed evaluation. Keep eligible scope and report the unresolved products. | `test_rep1_provider_success_does_not_complete_40_of_200`, existing completion regressions |

## Version and source boundaries

CPython release MSI encoding uses `major.minor.(1000 × micro + 10 × release
level + serial).0`. Decode only when the known publisher and versioned Python
release or Core Interpreter title agree with the computed version. The title
check also rejects inconsistent display versions and development encodings.
The product identity and component scope come from the existing mapping path.
The raw MSI value remains visible beside the interpreted value.
[CPython Windows version formula](https://github.com/python/cpython/blob/v3.12.4/PCbuild/python.props)
· [MSI version binding](https://github.com/python/cpython/blob/v3.12.4/Tools/msi/msi.props)

For NVD, an actual matching, current CPE catalogue entry supports exact-version
queries. Other accepted identities use family range queries and evaluate returned
criteria locally. A family with zero rows and no confirmed installed catalogue
entry remains partial. Fully compared, disjoint version ranges or known platform
constraints can establish exclusion. CNA requires an applicable explicit status
or default. Unknown ranges, product and scope evidence remain inconclusive.
[CVE Record format](https://cveproject.github.io/cve-schema/schema/docs/)
· [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
· [OpenSSL legacy versions](https://docs.openssl.org/3.0/man7/migration_guide/)

## Verification

Use the same frozen synthetic HOME/LAB fixture for both revisions. Its NVD IDs
and bounds are fabricated for testing. It pins product identity to isolate
applicability behavior and contains no endpoint identifiers from live runs.
Verify confirmed CVE counts, evaluated and eligible counts, the interpreted
Python release, the unresolved build boundary and the Shell-only BitLocker
indications in the generated report. Fresh collections correct the UTF-8 path.
Previously recorded evidence retains its original bytes and provenance.

| Frozen synthetic endpoint | 5.6.5 evaluated / eligible | 5.6.6 evaluated / eligible | Confirmed CVEs |
| --- | --- | --- | --- |
| HOME | 3 / 3 | 1 / 3 | 0 → 1 |
| LAB | 3 / 3 | 2 / 3 | 0 → 0 |

The HOME confirmation comes from the decoded Python version under the same
synthetic bound and same CPE identity. The scanner build boundary and the
unverified empty rows account for the lower evaluation counts. LAB retains
the confirmed Python upper-bound exclusion and the disjoint Linux constraint.

Run fresh standard-user EXE and PowerShell assessments on HOME and LAB before
release review. Confirm that each collection is accepted by the Lab, strings
retain their exact accents and symbols, and provider success and product
evaluation remain separate. The existing COL-1 release gate still applies.
