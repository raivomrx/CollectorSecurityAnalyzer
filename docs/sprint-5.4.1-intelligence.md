# Sprint 5.4.1: Software Intelligence correctness

## Product identity

Windows installation scope, architecture, and an exact embedded installed
version are removed only from the end of a display name. Helper, updater,
add-in, WebView, and edition distinctions remain separate. Canonical aliases
represent product families, never manually assigned CVEs. NVD discovery
aliases for Notepad++, Visual Studio Code, and NVIDIA GPU Display Driver
include public NVD identity references; candidate selection still requires
matching vendor and product components. Unknown or ambiguous identities remain
`NOT_EVALUATED` with a per-product trace and failure reason.
The provider query preserves the installed dotted version, including leading
zeros. When that exact version is absent from the CPE catalog, a family-range
query retrieves candidate CVEs for local applicability evaluation instead of
assuming there are no vulnerabilities.

When the collector explicitly reports Windows or Linux, a corresponding
platform-constrained CPE is preferred to the generic family CPE. Without OS
evidence, a platform-only CPE is not accepted. CPE edition and version-range
applicability checks remain separate and unchanged.

## Local CPE intelligence

`NvdCache` now maintains a persistent SQLite CPE discovery catalog under the
current user's CSA application-data directory. Each canonical product family
is queried once; successful discovery snapshots are refreshed after 14 days,
negative snapshots after 72 hours. A manual CVE cache refresh clears both
the catalog and NVD page cache. The catalog stores public CPE names, titles,
and deprecation flags, not endpoint evidence or credentials. NVD remains the
upstream source; this is a controlled local discovery index, not a full NVD
replica. CVE API responses retain their existing separate TTL cache.

Telemetry distinguishes `remoteCpeQueries`, `cpeCatalogHits`,
`cpeCatalogMisses`, NVD page requests, and rate-limit wait time. Endpoint runs
share the catalog even when each run creates a new resolver. The Lab progress
panel reports provider, phase, elapsed time, retry attempt, and wait state.
The operator can cancel a scan; cancellation reaches the worker and NVD
rate-limit wait, and the assessment remains incomplete rather than falsely
complete.

## Report semantics

Identified software counts require a successful CPE product mapping or a
completed version evaluation. Normalization confidence alone is not counted
as security-analysis identification. The report retains installation-record,
endpoint/product-version, and fleet-unique counting units. A completed
evaluation therefore cannot outnumber identified products. Provider success
without a reliable affected-version decision remains partial coverage. Generic
CVE-001 guidance is omitted from the remediation plan; product-level CVE
actions remain. SW-001 explains identity verification without implying malware.
Control titles use neutral names, control-result counts do not imply that all
controls were evaluated, and software versions are not repeated in the name
and version columns.

## Verification boundary

`tests/test_sprint541.py` uses sanitized HOME-shaped records for Notepad++
7.8.8, Visual Studio Code 1.137.0, Microsoft Teams 1.4.00.32771, and NVIDIA
Graphics Driver 466.11. It verifies canonical identities, strict CPE
selection, auditable nonmatches, persisted catalog reuse, and cancellation.
An 86-product controlled cold-start test uses 86 CPE and 86 CVE requests,
below the previous 275-request workload. These are deterministic simulated
provider responses, not a claim that a fresh live HOME scan takes a specific
time or finds specific CVEs. Live NVD performance and API-key provisioning
still require an authorized acceptance run.
