# CSA 5.6.8.5 — Collector and CVE reliability

Baseline: 5.6.8.4 / `0066285`. Private engineering candidate; public release
**HOLD**. The accepted customer Join design is preserved. Fresh HOME/LAB
acceptance belongs to the project manager and has not been declared complete.

## Evidence and root causes

The supplied EXE rejection correlation matched the local protected audit.
The same unused, unexpired, READY invitation had already delivered the EXE
five times to its authorized source. The old lifetime download limit then
returned generic `403 TRUST_NOT_ESTABLISHED`, although no enrollment had been
consumed. This is a delivery-quota bug, not evidence of missing customer consent
or a reason to remove source, expiry, integrity or one-use checks.

The successful Lab Quick Run and failing endpoint used different source-bound
invitations. Downloads on the failing source reached the server, but no accepted
submission or execution nonce followed. The old terminal message did not record
the failing client stage. The project manager confirmed there was **no separate
Windows security notification**. A particular antivirus, WDAC, execution policy
or TLS callback failure is therefore **not established** as the original HOME
cause. The new diagnostics and fresh endpoint test must resolve any remaining
failure; a same-host engineering pass does not prove that old HOME failure fixed.

For the CVE stall, analysis started at 10:24:42 UTC. The browser-heartbeat
watchdog began shutting down the backend at 10:26:44; collection cleanup followed
at 10:26:53. A negative Dell CPE response was cached at 10:26:46, after shutdown
had already begun. This explains loss of the local API and the browser's
`Failed to fetch`; it does not establish a provider outage, HTTP 429, or a clean
completed Dell evaluation. The protected Windows NVD key exists, and connection
testing succeeded. Missing-key speculation was excluded.

Old per-request timeout/retries were not a per-product wall-clock bound. A socket
timeout also does not bound a whole response, DNS or several sequential discovery
queries; see [Requests' timeout documentation](https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts).
Cancellation only checked around synchronous calls could not promptly release
the analysis worker during an active request.

## Collector changes and trust boundary

* Five transfers per 60-second window replace the lifetime five-transfer cap.
  The sixth returns `429 DOWNLOAD_RATE_LIMIT` and retry information. After the
  window the **same** authorized, unused package is downloadable again. Audit
  keeps cumulative downloads. Renewal does not extend expiry, revive a revoked
  invitation, change source scope or issue fresh execution authority.
* Precise rejection reasons, stage and correlation are recorded in the protected
  assessor audit/readiness view. Client diagnostics are bounded, schema checked,
  source scoped and marked `CLIENT_REPORTED`; they cannot establish a successful
  trust check, collection, receipt or acceptance.
* Start-only Quick Run uses a readable `powershell.exe -NoProfile
  -ExecutionPolicy Bypass -Command ...`, about 1,725 characters for the synthetic
  loopback fixture. It has no Base64 command, `IEX`, `DownloadString`, enrollment
  token or persistent `Set-ExecutionPolicy`. It works unchanged when pasted into
  PowerShell or CMD. Legacy manually provisioned transports retain their existing
  protocol and are outside this command change.
* The first transfer downloads only fixed `Start-CSASimple.ps1`, using Windows
  native `curl.exe` with a mandatory public-key pin. Its exact expected SHA-256
  is checked while a read lease prevents replacement, **before script execution**.
  The starter is part of the verified installed build seal and optional signing
  process. Missing/modified build files prevent Start preparation.
* `--insecure` is paired with mandatory `--pinnedpubkey` for the approved private
  self-signed Lab certificate; it is never an unpinned TLS fallback. The pinned
  key is derived from that same approved Lab certificate. The verified starter
  additionally checks the exact certificate fingerprint, validity dates and
  final EXE hash, then leases/rechecks the EXE before starting it. See the
  [curl public-key pin documentation](https://curl.se/docs/manpage.html#--pinnedpubkey).
* Typed .NET TLS/process callbacks avoid dependence on a PowerShell runspace on
  a network worker thread. Transfers have time/size limits and no redirect
  following. Temporary content has current-user/SYSTEM ACLs. Only Windows
  sharing/lock errors 32/33 receive bounded execution retries; trust failures
  remain failures.
* The native bound EXE still checks the original exact-byte assessor approval,
  signed manifest/envelope, session/source/endpoint/time/nonce and submission
  authority. EXE and both Quick Run shells use the **same engine, evidence
  schema, collection profile, privacy enforcement and server validation**.

This adds a transport to the already approved ADR 5682 private pilot; it creates
no new signing identity or delegation protocol. Independent trust remains the
assessor's verified local installation and approved independent handoff of its
correct Join origin/command. A hash supplied by an arbitrary untrusted web page
does not establish independent publisher trust. The operator must obtain and
verify this candidate through the approved channel. Production network Copy
remains `TRUST_ENROLLMENT_PENDING` until real Publisher/Lab identity enrollment.

Quick Run needs Windows PowerShell/.NET and native curl with working public-key
pin support. Missing tools, mismatches, expired authority or enforced policy fail
closed; EXE remains the other supported choice. GPO, AMSI, Defender, WDAC,
AppLocker and Smart App Control are not disabled, evaded or silently retried
through another transport. The process-only Bypass does not override GPO.

Diagnostics distinguish `CONNECTION_TLS`, `AUTHORIZATION`, `PACKAGE_INTEGRITY`,
`APPLICATION_CONTROL`, `COLLECTOR_EXECUTION` and `EVIDENCE_SUBMISSION`. The verified
starter preserves server correlation and recognized native reason codes, with
safe Windows start-error numbers when available. A failure before that starter
can run has a short local stage message; detailed server diagnostics remain in
Lab. Unreachable Lab cannot receive a client report. No stage guess constitutes
proof that a security product blocked execution.

## CVE execution, checkpoints and recovery

The per-product wall-clock budget defaults to **60 seconds**, including NVD
discovery, pagination, HTTP retries, 429 waiting and rate limiting. Configure
`CVE.ProductDeadlineSeconds` for source/CLI operation or launch the packaged Lab
with process environment `CSA_CVE_PRODUCT_DEADLINE_SECONDS`. This changes the
wait budget, not identity/applicability confidence or NVD request-rate policy.
Timeout produces `PRODUCT_DEADLINE_EXCEEDED` and PARTIAL/NOT_EVALUATED for that
product, then continues. It never means zero CVEs or confirmed absence.

Active requests are polled for cancellation/deadline rather than blocking the
analysis worker. Responses have bounded sizes and are closed; abandoned results
cannot publish to the cache or findings. Provider progress includes elapsed time,
retry attempt, remaining product budget and rate/backoff waiting. Safe transport
logs include endpoint label, attempt, status, elapsed time and abandonment, with
no API key, request parameters or response body added by this change.

Provider work uses bounded daemon capacity (four network calls and four
enrichment calls). OS-level DNS/socket operations cannot be forcibly killed by a
Python thread: a cancelled in-flight call can finish later, its result discarded.
If all slots remain stuck, subsequent work becomes explicitly incomplete and can
be retried after transport recovery/restart; it does not create unlimited threads.
Cancellation cannot interrupt arbitrary filesystem/HTML generation, so the local
UI can remain CANCELLING briefly while retained results are finalized.

Product checkpoints are atomic, private and bound to input, version, CVE
configuration and mapping digests. Fresh completed rows are reused, incomplete
rows retried; stale rows are re-evaluated. Already confirmed findings remain
when a retry is uncertain, and are replaced only by a completed authoritative
evaluation. Cache TTL/provenance and encrypted Windows-user NVD storage remain.
No checkpoint or customer inventory is shipped to GitHub.

The CVE lock is separate from the collection/API lock. Job markers persist
progress and terminal state. Restart restores RUNNING/CANCELLING as
`INTERRUPTED / PARTIAL`, including legacy RUNNING findings without a marker;
the user explicitly runs analysis again to reuse checkpoints. This does not
silently restart an agent. Late callbacks cannot reopen a terminal job or change
a newer job. Starting a new scan invalidates the previous report link. After
cancel/recovery, allow an explicitly incomplete report; never display a clean
COMPLETE assessment for unfinished work.

The heartbeat timeout is 300 seconds and does not shut down while analysis is
active. Once work ends it grants a fresh reconnect interval. The UI refreshes
heartbeat on visibility return and distinguishes a timed-out/unreachable API
from a provider failure instead of displaying only `Failed to fetch`.

## Verification and operator acceptance

Automated regressions cover actual Windows EXE/PowerShell/CMD execution,
unchanged signed-receipt/profile/privacy parity, wrong source, replay/revocation,
expiry, modified installed files, modified EXE/starter, wrong TLS/digest,
recoverable transfer quota and untrusted client diagnostics. CVE tests cover
slow/network failures, deadlines, HTTP 429, retry/rate waits, active-request
cancellation, confirmed findings in cancelled HTML/metadata, resume-only-incomplete
checkpoints, responsive local API, stale heartbeat and job recovery.

On the developer's existing Windows host, the actual frozen 5.6.8.5 application
completed EXE, PowerShell and CMD collections, verified signed receipts and code/
profile/privacy parity, and generated HTML. The opt-in actual packaged NVD test
used the existing user-bound encrypted key: connection succeeded, cancellation
completed in 1.781 seconds (1.656 after recovery), maximum measured read-API
response was 0.828 seconds, forced test-process termination recovered as
INTERRUPTED/PARTIAL, incomplete HTML was generated, and accepted evidence hashes
were unchanged. These are local engineering observations, not a performance
guarantee or a fresh HOME/LAB acceptance claim. Final exact-commit CI, installer
hash/signature and installed-candidate results are recorded in the delivery handoff.

Reproduction helpers (private short paths; do not upload their output):

```powershell
python scripts/Test-PackagedCustomerJourney.py --executable <installed-CSA-Lab.exe> --output <new-private-root> --execute --browser <Edge.exe>
python scripts/Test-PackagedCveRecovery.py --executable <installed-CSA-Lab.exe> --data-root <private-root>/assessments --execute
```

The CVE helper requires the existing encrypted NVD key provisioned in that
isolated application's config directory. It intentionally terminates only its
own process to test recovery. Real user/customer assessments remain untouched.
Live upstream CVE requests are opt-in and are not a nondeterministic CI gate.

Project-manager HOME/LAB check after installing the exact delivered candidate:

1. Create a **new assessment**, confirm the approved direct LAN/source scope,
   and press Start Collector. Use the unchanged two-method Join page.
2. On HOME and LAB separately: download one EXE and run; obtain the accepted
   receipt. Use a fresh invitation for each PowerShell/CMD Quick Run and obtain
   its accepted receipt. Confirm no persistent execution-policy change.
3. Repeated authorized downloads must recover after the short window. Expired,
   revoked, wrong-source and changed packages must stop without evidence receipt.
   If any client fails, record its stage/code/correlation and inspect Lab
   diagnostics; do not disable security software.
4. Verify NVD settings/connection, run the real inventory including the previously
   slow product, watch live progress, cancel during a provider call/wait, and
   confirm the local UI stays available. Retry incomplete rows and generate an
   honestly incomplete report when appropriate; verify known CVEs remain.
5. Confirm both endpoint results and report. Architect review and explicit
   project-manager live acceptance remain required before lifting release HOLD.

No evidence schema, credential/privacy boundary, BitLocker/AV/password/MFA
semantics, CPE identity requirement, applicability confidence, risk trigger or
KEV priority was weakened. No raw customer evidence or secrets belong in this
commit. The next step is this targeted live acceptance and review, not 5.7 scope.
