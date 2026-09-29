# CSA 5.5 - Fleet Software Intelligence quality

## Scope

Sprint 5.5 makes product identity correctness a prerequisite for CVE coverage.
It does not promote uncertain software identities merely to increase the
reported evaluation rate. All committed regressions use synthetic or sanitized
data. No raw multi-endpoint customer evidence is included in the repository.

## Product identity decisions

Software normalization now records a privacy-safe decision trace containing:

- the candidate canonical identity;
- positive evidence used for the decision;
- guardrail rejections;
- final confidence and schema version.

Release generation, product family, component role, edition, platform and
channel remain identity-defining when present. Packaging attributes such as
x86/x64 and installation scope may be removed only when they do not change the
product identity. In particular, Visual C++ 2012 (11.x), 2013 (12.x) and named
14.x generations are kept distinct. A conflicting display-name generation and
version family is rejected instead of being assigned fuzzy-match confidence.

Parent products and components such as Edge/WebView2, Teams/Meeting Add-in and
CCleaner/Update Helper do not inherit one another's vulnerability identity.

## CPE intelligence repository

The persistent CPE catalog uses schema `cpe-intelligence-2.0`. A catalog record
stores its source, source version, creation time and expiry time. Positive
records have a bounded 14-day TTL and negative discovery results a 72-hour TTL.
A stale record is diagnostic input only: CSA attempts controlled provider
synchronization and never reports stale data as fresh.

Discovery work is keyed by canonical vendor/product/query identity and reused
across endpoint product instances. Resolver telemetry distinguishes memory
hits, fresh catalog hits, negative hits, stale records, synchronizations and
remote CPE queries. Existing CPE 2.3 escaping, environment constraints and the
Notepad++ family-range behavior remain unchanged.

## Terminal outcomes

Every software pipeline result can expose one stable terminal reason:

`UNSUPPORTED_COMPONENT`, `CUSTOM_OR_INTERNAL_SOFTWARE`,
`NO_AUTHORITATIVE_MAPPING`, `AMBIGUOUS_IDENTITY`, `VERSION_UNAVAILABLE`,
`VERSION_NOT_COMPARABLE`, `EDITION_UNKNOWN`, `CPE_VERSION_NA`,
`APPLICABILITY_INCOMPLETE`, `PROVIDER_ERROR`, `PROVIDER_RATE_LIMIT`,
`PROVIDER_STALE`, or `EVALUATION_COMPLETED`.

These codes separate permanent identity gaps from retryable provider failures.
The unified report includes product-level diagnostics and a fleet-deduplicated
analyst worklist. A partial product remains partial even when some confirmed
CVEs are present; an evaluated-clean statement still requires successful,
complete version applicability evaluation.

## Report semantics

Software coverage reports distinct counting units:

- installation records;
- endpoint/product-version instances;
- CVE-eligible instances;
- fully evaluated eligible instances;
- eligible partial, not-evaluated and provider-failure instances;
- noneligible or unsupported components;
- all-software instances not completed;
- fleet-unique product/version identities.

Reliable identification is based on security-analysis product mapping, not
only initial normalization confidence. Therefore the identified count cannot
be lower than the number reported as fully evaluated.

A confirmed affected CISA KEV creates a P1 remediation work item. This task
priority is distinct from CVSS, finding severity, source trust, applicability
and the overall risk model. KEV presence does not claim that every exploitation
path is available on the endpoint.

## AV reconciliation

Windows Security Center registrations and installed security-product inventory
are separate evidence sources. An inventory-only product is shown as
`INSTALLED_NOT_REGISTERED`, `ROLE_UNKNOWN` and `NOT_EVALUATED`; installation
does not prove active real-time protection. Defender or another registered AV
remains the posture authority, including existing source-conflict and
freshness semantics.

## Verification boundary

The automated suite covers adversarial identities, versioned cache lifecycle,
terminal reasons, fleet counting, installed-versus-registered AV and a full
unified-report KEV priority flow. Existing Notepad++, Adobe, source-trust,
BitLocker, credential-exposure and password-policy regressions remain active.

A controlled cold/warm benchmark requires the same locally retained accepted
HOME evidence, the same code revision and an explicitly selected API-key mode.
It is intentionally not inferred from changed historical reports or synthetic
tests. Record request counts, CPE discovery, rate-limit wait, provider fetches,
cache hits/misses, provider errors and wall time during post-review live
acceptance. No release or acceptance tag is created by this sprint handoff.
