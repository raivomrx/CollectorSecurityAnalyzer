# CSA 5.6.0 — review candidate

This change improves BitLocker evidence interpretation, vulnerability applicability,
and executive identity reporting. It is **not a final accepted release**. The
remaining acceptance gate is fresh, readable HOME BitLocker evidence and Architect
review. No release or tag is created.

## BitLocker

The collector runs the Get-BitLockerVolume, WMI, manage-bde and Shell providers
even after an earlier success. Reliable disagreements, including an explicit
transition conflicting with a completed state, produce SOURCE_CONFLICT/PARTIAL.
Provider execution and interpretation status are separate diagnostics.

The manage-bde parser requires successful status execution, a consistent numeric
percentage, explicit conversion state and protection evidence before accepting
fully decrypted / 0% / protection off. A failed second protection query does not
invalidate an otherwise explicit successful status response. English, German and
French status field formats are recognized; other formats fail closed. Only
bounded status fields and exit/parser diagnostics are retained, never recovery keys.

Enabled, fully decrypted, encryption/decryption progress, paused, suspended,
locked, conflict, error and unavailable evidence remain distinguishable through
normalization, control evaluation and reporting. Shell 0/null/empty and policy
intent cannot establish disabled protection.

The retained HOME collector evidence contains Get-BitLockerVolume/WMI access
denials, a failed manage-bde query and Shell 0. The user confirmed on 2026-10-02
that the successful manual manage-bde check used an administrator window. The
standard-user collector's retained evidence therefore still correctly produces
NOT_EVALUATED. A parser cannot recover facts that the provider did not return.
Fresh HOME collection with an explicitly authorized readable provider is required
to validate NOT ENABLED / FULLY DECRYPTED on the actual endpoint. No silent
elevation or substitution of the user's statement for collector evidence occurs.

## Software intelligence

Version/environment constraints are conjunctive: an authoritative version or
platform mismatch excludes a criterion even if another constraint is unknown.
A matching version still requires its edition/platform/environment constraints.
Bare wildcard and NA CPE versions do not prove universal applicability.

One explicit publisher alias maps Tomasz Mon / USBPcap to
`usbpcap_project:usbpcap`. Its provenance is the author's
[software page](https://desowin.org/software.html) and
[USBPcap repository](https://github.com/desowin/usbpcap).
Identity confidence thresholds, ambiguous-family rejection and component isolation
are unchanged. Existing mainstream, generation, edition and platform regressions
remain active.

Resolver decisions now include the raw identity, architecture, normalization
trace, alias/mapping rules and thresholds in their memory-cache identity. Cached
raw CPE records are reranked after a rule change. The existing
`cpe-intelligence-2.0` repository, 14-day positive and 72-hour negative catalog TTL,
stale/fresh distinction and provenance remain intact. Telemetry separates logical
CPE/CVE queries from remote CPE/CVE requests and measures applicability duration.

NVD, CVE Program/CNA and CISA KEV remain the intelligence providers. No new
vendor-specific adapter was enabled. Investigated OneDrive MSRC data describes
channel/install-scope qualifications in prose rather than safe structured bounds;
WebView2 lacks a verified mapping to Edge's vulnerability family. These gaps remain
explicit rather than parsing prose into invented ranges or merging components.

Each generated report also writes `intelligence-worklist.json` alongside the HTML:
canonical families, raw display variants, versions, instance/endpoint counts,
terminal-reason distribution, candidate sources/CPEs, blockers and resolver action.
The client-facing top-gap table omits developer resolver instructions. Sorting
prioritizes eligible instances, security relevance and repeated endpoints.

## Retained HOME reanalysis, 2026-10-02

This reuses the accepted 5.5.1 collector evidence; analysis/report version is 5.6.0.
It is not a fresh HOME collection. No raw customer data is committed.

| Metric | Accepted baseline | Reanalysis |
| --- | ---: | ---: |
| Installation records | 111 | 111 |
| CVE-eligible instances | 97 | 97 |
| Fully evaluated | 20 (20.6%) | 23 (23.7%) |
| Eligible partial | 9 | 7 |
| Eligible not evaluated | 68 | 67 |
| Provider failures | 0 | 0 |
| Noneligible / unsupported | 14 | 14 |
| Unique confirmed CVEs | 278 | 302 |
| Confirmed software/CVE relationships | 280 | 304 |
| KEV | 1 | 1 |

All three terminal-state improvements preserve normalized identity:

| Raw product / version | Canonical identity, old = new | Old reason → new | Mapping change | Confirmed CVEs |
| --- | --- | --- | --- | --- |
| USBPcap 1.5.4.0 / 1.5.4.0 | Tomasz Mon / USBPcap | NO_AUTHORITATIVE_MAPPING → EVALUATION_COMPLETED | None → `cpe:2.3:a:usbpcap_project:usbpcap:1.5.4.0:*:*:*:*:*:*:*` | 0 → 0 |
| Malwarebytes version 5.7.0.328 / 5.7.0.328 | Malwarebytes / Malwarebytes | EDITION_UNKNOWN → EVALUATION_COMPLETED | Unchanged `cpe:2.3:a:malwarebytes:malwarebytes:*:*:*:*:*:windows:*:*` | 0 → 0 |
| Bonjour / 3.1.0.1 | Apple / Bonjour | APPLICABILITY_INCOMPLETE → EVALUATION_COMPLETED | Unchanged `cpe:2.3:a:apple:bonjour:*:*:*:*:*:*:*:*` | 1 → 1 |

USBPcap uses the validated publisher alias plus the exact catalog version.
Malwarebytes and Bonjour use authoritative exclusions before unresolved edition
constraints; the retained-source offline replay independently reproduces these
two improvements. Bonjour's confirmed vulnerability remains visible.

Across all 111 outcomes, NO_AUTHORITATIVE_MAPPING changes 68 → 67,
APPLICABILITY_INCOMPLETE 8 → 7, EDITION_UNKNOWN 1 → 0; UNSUPPORTED_COMPONENT
stays 10 and VERSION_UNAVAILABLE stays 4. These are not the eligible-incomplete
denominator.

The 24 additional confirmed CVEs belong to Chrome 154.0.8037.59. All 24 were absent
from the retained Chrome NVD response and present in the refreshed response.
For example CVE-2026-102299 gained applicability data modified 2026-10-01, with an
exclusive upper bound of 154.0.8037.92. Chrome remains PARTIAL because other records
still lack reliable bounds. No new CVEs were inserted by the alias or hardcoded.
The full identifier/range comparison stays in private acceptance artifacts.

Top remaining gaps include Visual C++ 2012/2013 families (three eligible instances
each), Chrome, OneDrive, Teams, Visual Studio Code, LibreOffice, WebView2, NVIDIA
components and Python. Historical wildcard/NA applicability and missing exact
component mappings remain unresolved. The improvement is three instances, not
broad completion of these mainstream families; Architect review must assess this
against the requested material-improvement criterion.

First reanalysis took 102.51 s using 7 local mappings, 90 CPE catalog hits
(64 negative), zero remote CPE queries, 30 remote NVD CVE requests and 336 CNA
requests; provider errors and stale hits were zero. A subsequent cached rerun took
3.65 s, with 30 NVD response-cache hits, 336 CNA cache hits and zero remote
CPE/CVE/CNA requests. Rate-limit wait was effectively zero. Applicability evaluation
took about 0.06 s. No separate vendor advisory requests occurred. The first pass
used an already-populated CPE catalog, so this is not a controlled cold-cache A/B
benchmark. A private combined worklist also includes retained earlier RAIVO-TEST
diversity evidence, explicitly labelled as a historical snapshot.

## Identity and report semantics

Executive Summary now shows password policy, MFA, credential-capture exposure and
SMB relay exposure independently. Local minimum length is evaluated against the
configurable ACC-006 baseline (default 15), with history and lockout posture.
Domain-joined endpoints explicitly show DOMAIN_POLICY_NOT_EVALUATED when only
local policy is available. Actual password strength is not tested.

MFA supports ENFORCED, PARTIAL, NOT_ENFORCED, NOT_EVALUATED and SOURCE_CONFLICT
through a typed trusted-provider boundary. No live IdP adapter is enabled in 5.6;
endpoint JSON cannot claim enforcement. Join and Windows Hello provisioning
booleans are supporting signals only. The collector retains no PRT/token material.

HOME shows local policy FAIL (minimum 0, required 15, history 0, lockout threshold
0), scope LOCAL_POLICY and MFA NOT_EVALUATED. Capture and relay prerequisites remain
independently reported with partial evidence. Active AV coverage remains 1/1 and
full protection health 0/1 due to the existing freshness conflict.

NVD provider health is SUCCESS while evaluation coverage is PARTIAL (23/97).
Display-only version cleanup handles Wireshark's architecture suffix and Python's
different display/MSI versions without removing Office/Visual C++ release years.

## Verification and acceptance artifacts

- Full Python suite: 503/503 passed, ResourceWarnings 0; final telemetry-focused
  regression run: 73/73 passed.
- Full Windows PowerShell/Pester suite: 86/86 passed, none skipped.
- New tests cover reliable provider fallback, locale parsing, contradictory
  sources, transitions, suspended/locked states, endpoint-only MFA, future IdP
  observations, policy scope, applicability conjunctions and identity-rule cache
  invalidation. Existing identity/source/TTL/risk regressions remain active.
- Synthetic 1/10/50/100 endpoint renders: 0.083 / 0.208 / 0.742 / 1.572 s.
  The 100-endpoint HTML is 6,455,621 bytes. Repeated model/render determinism,
  report SHA-256 verification and Estonian UTF-8 round-trip pass.
- Collector, packaged Lab and NSIS installer build pass. Packaged startup,
  isolated localhost UI, version 5.6.0, NVD configuration endpoint and bundled
  discovery aliases pass. The smoke test does not overwrite the installed Lab.
- Local unsigned installer created 2026-10-02 05:46:19 UTC / 08:46:19 Tallinn;
  SHA-256 `b9571515df728e1d2e788b8550cfc9387316e4d2ede6dbdd4eddc263ce8fdbc9`.
  The exact committed CI installer has its own BUILD-INFO.md timestamp/hash.
- GitHub Actions and the final commit identity are recorded in the developer
  handoff after push; local build success is not a substitute for CI success.
- Private `test-artifacts/sprint56/` contains before/after models, terminal changes,
  source delta provenance, telemetry, worklist, generated HOME HTML and validation
  logs. Report creation uses cached findings and does not require web access.

## Security answers

| Question | Answer |
| --- | --- |
| Did identity-confidence requirements weaken? | NO |
| Did CVE source-trust requirements weaken? | NO |
| Did risk-model semantics change? | NO |
| Did endpoint credential material begin to be collected? | NO |
| Was Active Responder introduced? | NO |
| Was MFA inferred from endpoint-only evidence? | NO |
| Were raw customer datasets committed? | NO |

DPAPI current-user NVD key storage and optional environment fallback are unchanged.
No capture, relay, cracking, security-control disabling or silent elevation was
added. Final release/tag remains withheld pending Architect and HOME acceptance.
