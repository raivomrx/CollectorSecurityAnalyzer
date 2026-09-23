# CSA 5.4.3 — live acceptance correctness corrections

## Software intelligence

Remote discovery attempts bounded, deduplicated keyword variants from an audited
alias, normalized product, vendor/product and original inventory name. Vendor
identity and product family must both match; a title cannot compensate for a
wrong family. Helpers and runtimes retain their component identities. Deprecated
and close competing candidates cannot silently become a reliable selection.

NVD version rows are collapsed only after canonical vendor/product plus
edition/platform grouping. Different catalog versions and equivalent spelling
variants are one product family, while product years and real edition/platform
differences remain separate identities. If the installed version is catalogued,
CSA selects that exact family row. Otherwise it retains the bounded
`FAMILY_RANGE` query and evaluates installed-version applicability. The Notepad++
7.8.8 regression uses multiple NVD-shaped version rows and both observed vendor
spellings; no CVE or product-specific result is forced into the pipeline.

`software/cpe_discovery_aliases.json` is a discovery aid, not a hardcoded final
CPE/CVE result. Lightroom Classic requires `adobe:lightroom` with software edition
`classic`; Premiere Pro uses `adobe:premiere_pro`; The Document Foundation maps to
the catalog vendor/product `libreoffice:libreoffice`. Candidate queries, counts,
scores, edition, version availability, rejection and final selection are retained
under `discoveryTrace` and visible in advanced diagnostics/report details.

When a catalogued family does not contain the installed version, the
`FAMILY_RANGE` query rebuilds a CPE 2.3 name from canonical components. Every
reserved character is escaped according to the formatted-string component
contract; wildcard and not-applicable values retain their defined meanings.
This fixes families such as `notepad\+\+` without a product-specific exception.
The regression uses an uncatalogued version and a generic product containing
reserved characters.

The applicability evaluator retains a validated application's software edition
when checking an NVD edition constraint. Unknown editions remain unevaluated;
different editions do not match. OS constraints and version ranges still apply.
The public Lightroom fixture traverses normalization, discovery, NVD applicability
and CNA trust resolution, including the Adobe vendor-advisory link. No production
code chooses a result based on a hardcoded CVE ID.

Microsoft Edge and WebView2 Runtime normalize separately. CCleaner Update Helper
cannot inherit the main product identity. Completed Audacity evaluation with zero
matching vulnerabilities remains a clean evaluated result, even in an otherwise
partial assessment.

The Audacity discovery alias uses the active NVD `audacityteam:audacity` family;
the deprecated `audacity:audacity` row is retained as a negative fixture. This
preserves Audacity 2.4.2's completed zero-match result through current discovery.

## BitLocker

The provider sequence is Get-BitLockerVolume, Win32_EncryptableVolume, manage-bde,
Shell property and policy indication. A reliable OS protection state ends the
sequence; earlier errors remain visible. Policy alone does not prove actual disk
protection. If every provider fails, a null OS protection setting retains the
complete attempt list without increasing collected evidence.

Each attempt records execution/collection status, raw-state availability,
minimized raw state, parsed state, error category, confidence and selection.
Shell raw `1` means protected, `2` means disabled, `3`/`4` are transitional and
`5` is suspended protection. Null, empty and unrecognized values never become
disabled. The null-accepting parameter removes the earlier PowerShell binding
failure; it does not invent a value for an unavailable Shell property.

## Accounts and passive credential exposure

`NetUserModalsGet` levels 0 and 3 provide locale-independent password and lockout
policy. API buffers are always freed. Password and lockout reads fail independently.
The collector exposes minimum length, minimum/maximum age, history, lockout
threshold, duration and observation window; unavailable data remains explicit.
This measures configured policy, not the strength of anyone's actual password.
ACC-006 reads the minimum-length threshold from the selected policy profile; the
default single-factor baseline requires 15 characters.
Its client finding includes the observed value, required minimum, concrete policy
change and recollection verification. It explicitly states that the result
assesses `LOCAL_POLICY`, not domain-effective password policy. Domain/effective
policy remains a separate capability. ACC-009 correlates its count with
`LOCAL_USERS` and lists the enabled local accounts where `PasswordRequired=false`.
No password inspection, capture, relay or cracking is performed. Active Responder
remains a separately authorized workflow.

SMB server/client, optional SMBv1 client feature, LLMNR, NBT-NS, outbound NTLM,
LM compatibility and WinHTTP WPAD use independent provider boundaries. Registry
access denial is distinct from an absent policy with a documented default. Null
SMB fields are not converted to false. Adapter default states remain partial.

Credential Exposure Posture now reports `Credential Capture Exposure` separately
from `SMB Relay Exposure`. LLMNR/WPAD plus outbound NTLM can establish capture
prerequisites while NBT-NS remains partial. SMB signing is evaluated only in the
relay posture. Exposure state and evidence completeness are separate fields, so an
unrelated collection gap cannot suppress already-confirmed prerequisites. A single
weak setting still does not establish exploitability. Domain-effective policy,
exceptions and network reachability are not established by these local reads. No
capture, relay, cracking or credential retention is introduced. Active Responder
validation retains its separate authorization workflow.

## NVD key and performance

CSA Lab Settings → Vulnerability Intelligence supports set/replace, remove and
connection test. The key is encrypted with Windows current-user DPAPI and stored
outside assessment directories as `config/nvd-api-key.dpapi`. UI/API responses show
presence only. No plaintext settings, report fields, exports or command-line
arguments carry the key. HTTP errors redact a provider echo of the key; diagnostic
log sanitization recognizes API-key labels. With no saved key, `NVD_API_KEY` remains
supported. No key is required for normal operation.

Advanced telemetry includes local mapping, CPE discovery, NVD request count,
rate-limit wait, CPE/CVE cache hits and misses, CVE retrieval, CVE Program time and
cache/request counts, CISA KEV time and total analysis time. These durations overlap
(for example rate-limit wait is included in provider duration); do not add every
field together. Fresh and negative NVD responses retain TTL-based persistent
caching. Immediate reruns reuse fresh caches; expired and stale behavior remains
explicit. Rate limits and provider retry rules are preserved.

## Report semantics

CVEs within each product are ordered by CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN;
ties use confirmed KEV, confirmed applicability, CSA priority, descending CVSS and
CVE ID. Primary remediation points to the installed product's vendor updates or
mitigations. P1 does not imply proven exploitation. BitLocker protection, Secure
Boot state, ACC-006 and ACC-009 use neutral control names in both rule metadata and
knowledge. SW-001 describes unreliable product identification for security analysis,
not malware.

Active Defender freshness uses direct `Get-MpComputerStatus` signature age for
policy evaluation and treats Windows Security Center as corroborating evidence.
A disagreement is shown as `SOURCE_CONFLICT`; it cannot silently produce an
AV-001 partial result beside a DEF-003 pass. Third-party AV and Defender passive
mode remain distinct. Endpoint detail includes the registered AV inventory with
per-product primary/passive role, protection state, freshness and evidence source.
This posture does not claim that an endpoint is malware-free.

Fleet reporting separates endpoints with active AV coverage from endpoints whose
full anti-malware health posture passed. Localized Defender registrations collapse
to the canonical `Microsoft Defender Antivirus` identity. Product/agent and engine
versions are distinct from signature version and signature update time; third-party
freshness retains its explicit evidence source.

The client-facing endpoint summary no longer displays a meaningless numeric
`Risk score 0.0`. Endpoint rating and evidence coverage remain visible, while the
internal prioritization score is retained for assessment logic.

Collector evidence, online submissions, encrypted offline packages and unified
HTML preserve UTF-8 text end to end. Regressions cover Estonian computer, user,
software and publisher names and UTF-8-without-BOM collector output.

Product-level CVE titles, verification text and priority actions remove an
installed version already embedded in the product display name before appending
the separate installed-version field.

## Verification and evidence boundaries

Run `python -W error::ResourceWarning -m unittest discover -s tests -q` and
`scripts/Invoke-CollectorTests.ps1`. `tests/test_sprint54.py` covers public-source
identity/trust, negative editions and environment, runtime/helper separation,
persistent positive/negative caches, DPAPI lifecycle, HTTP CSRF and key secrecy,
password-control semantics and accepted evidence through report rendering.
`tests/powershell/Sprint54.Tests.ps1` covers provider fallback and isolation.
Existing Illustrator/CNA and risk regressions remain in the full suite.

Local 5.4.3 correction verification: **471 Python tests passed; 78 Pester tests
passed; Pester FailedCount 0**. `test-artifacts/pester-results.xml` was generated.
Python ran with `ResourceWarning` promoted to an error. The focused suite covers
standards-compliant family-range CPE escaping, split capture/relay exposure,
policy-profile thresholds, account correlation, AV coverage/version semantics and
the online/offline Estonian UTF-8 round trip. The retained 5.4.2 suite covers
real-shaped multi-row Notepad++ family
resolution, absent-version family-range fallback, Defender/Windows Security
Center freshness conflicts, third-party/passive AV inventory, concrete ACC-006
semantics and duplicate-version report rendering.
The user authorized reusing the existing HOME evidence rather than recollecting
HOME. That unchanged 118-record, 86-eligible dataset improved from 12 to **19 fully
evaluated instances**, with **450 confirmed unique CVEs** (previously 387).
Lightroom Classic 8.4, Premiere Pro 13.1.3 and LibreOffice 25.8.3.2 completed with
16, 44 and 1 confirmed CVE respectively. Audacity 2.4.2 completed with zero matches.
The WebView2 result remains unevaluated independently of the Edge browser.
HOME's missing old BitLocker/password evidence is not invented by reanalysis.

Fresh standard-user collection was performed on **RAIVO-TEST**, not HOME. Its
BitLocker Shell property returned 1 after earlier provider failures. The measured
empty-cache run took **1733.198 s**, and the immediate warm run **7.567 s**.
No NVD API key was configured. The cold run made 275 NVD requests and spent
1269.037 s waiting for rate limits; the warm run made zero NVD and CVE Program
requests. This is a measured bottleneck, not a claim that cold scanning became
faster. After the final Audacity/priority corrections, HOME's cached reanalysis
took **3.951 s**, with zero NVD/CVE Program requests.

On 2026-09-17, before the 5.4.2 correction, the existing HOME accepted evidence
was analyzed with the NVD
key configured in CSA Lab's Windows-user DPAPI store. The isolated fresh-cache
run took **236.948 s** (118 NVD requests, 29.899 s rate-limit wait); its
immediate warm run took **3.126 s** (zero NVD and CVE Program requests).
Both runs remained **PARTIAL**, with 19 of 92 eligible products evaluated and
461 confirmed CVEs. A key improves request throughput but does not itself
resolve product mapping or applicability gaps. The earlier no-key cold/warm
timings above are from RAIVO-TEST and an earlier code revision, so the timing
ratio is indicative rather than a controlled same-dataset A/B comparison.
The ignored local benchmark stores only aggregate metrics and analysis output;
all 13 generated files were checked for the raw key, with no match.

A post-5.4.3 multi-endpoint live rerun remains the final operational acceptance
step. This correction is intentionally not tagged or declared the accepted final
release. The
automated regression and retained real-shaped catalog data establish the correct
family-selection contract without claiming that a new HOME report has already
been generated. A cache-only check against the retained HOME NVD catalog resolved
Notepad++ 7.8.8 from 308 accepted version rows to one canonical family and the
exact installed-version CPE, with no remote request.

The packaged application startup, settings endpoint and discovery alias asset
were checked locally. The NVD settings dialog was inspected in the browser.
The report preview was blocked by the browser client; generated HTML/model and
report integration assertions were verified, without claiming visual inspection
of the final report.

HOME evidence, complete remaining-product lists, timing artifacts and generated
client reports stay in ignored local acceptance storage. Public fixture data is
documented in `tests/fixtures/sprint54/README.md`. mCollector was reviewed only as
a reference; its implementation was not copied.

The two added password-policy evidence IDs are optional additive manifest entries.
Existing IDs and the schema contract are preserved.

## Regression declaration

* CVE applicability engine behavior weakened: **NO**
* Source-trust requirements weakened: **NO**
* Risk engine changed: **NO**
* Standard collection automatically performs active Responder validation: **NO**
* Credential material retention introduced: **NO** (the optional NVD service API
  key is encrypted configuration, not captured endpoint credential material)
* Breaking evidence-schema change: **NO**
