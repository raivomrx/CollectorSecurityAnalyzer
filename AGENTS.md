# CollectorSecurityAnalyzer (CSA) — repository instructions for Codex

These are persistent **repository-wide** instructions. Read the current sprint brief,
`README.md`, relevant `docs/` files, and applicable nested `AGENTS.md` files before
changing code. The current sprint brief defines scope; this file defines durable
engineering and delivery constraints. Do not treat a past sprint's feature list as
an instruction to implement it again.

## Project and roles

- **Project manager / live tester:** the user sets priorities, approves scope and
  performs real Windows endpoint and customer-environment acceptance tests.
- **Architect / reviewer:** ChatGPT helps define architecture, acceptance criteria,
  review findings and targeted correction inputs.
- **Developer:** Codex implements, documents, tests and delivers the changes.
- CSA is an evidence-first **Windows security assessment platform**, not a
  persistent endpoint agent or simply a system inventory tool.
- Keep responses and handoffs clear enough for the project manager to verify.
  If a sprint requirement is ambiguous, state the assumption; ask only when a
  decision cannot be made safely and within the agreed scope.

## Non-negotiable architecture and security boundaries

- Default collection is **standard-user, one-shot, passive, no UAC elevation**.
  No hidden persistence, auto-start, unattended background agent, or silent
  endpoint configuration changes.
- Preserve collection/evaluation separation; protect assessment/session binding,
  short-lived enrollment tokens, replay/nonce checks, integrity manifests,
  certificate pinning, offline encryption, evidence schemas and audit trail.
- Collector executables and the PowerShell-compatible distribution must share
  the **same Collector engine, collection semantics and trust checks**. Do not
  make a weaker alternate path. Fail closed on integrity and authorization errors.
- Do not disable endpoint security, weaken PowerShell/system security policy,
  bypass AppLocker/WDAC, or silently escalate privileges to make collection work.
  Handle endpoint-security file locks with bounded, narrowly classified retries;
  do not retry or ignore hash mismatches or unsafe package paths.
- **Passive credential/Responder posture** is not a credential-capture result.
  Any active validation requires a distinct, explicit scope and authorization;
  never enable capture, relay, cracking, hash dumping or credential retention as
  a side effect of ordinary assessment collection.
- Preserve minimum collection and privacy boundaries: do not collect or export
  passwords, NT hashes, NetNTLMv2 challenge responses, tokens, browser secrets,
  private keys, BitLocker recovery keys or user-document contents in the standard
  collector. A future specially authorized active-validation component needs
  separate review and rules.
- Never place NVD API keys, session secrets, customer datasets, usernames,
  hostnames, internal addresses, identifying endpoint evidence or sensitive
  response material in repository commits, test fixtures, CI logs, issue text,
  demo reports, generated output or handoff documents. Use synthetic/sanitized
  fixtures. Preserve secure DPAPI storage and the optional `NVD_API_KEY` runtime
  environment fallback without printing values.

## Evidence correctness — never invent a security state

- Make findings traceable to collector evidence, specific evaluation logic,
  source, time, confidence, affected endpoint and remediation.
- Keep `PASS`, `FAIL`, `PARTIAL`, `NOT_EVALUATED`, `ERROR` and source conflicts
  semantically distinct. Access denied, absence of evidence, or failed parsing
  is **not** proof that a protection is disabled or a vulnerability is absent.
- **BitLocker:** represent protected, fully decrypted/not enabled, transitional,
  suspended, locked, unknown and source-conflict states faithfully. Shell null
  or raw `0` alone must never be interpreted as disabled. A trustworthy complete
  `Fully Decrypted / 0% / Protection Off` observation may establish not enabled.
  Do not collect recovery keys. Record provider attempts and selected evidence.
- **Passwords:** a local password-policy minimum is not the current user's
  password strength, and local workstation policy is not domain-effective policy.
  The configurable 15-character single-factor baseline is a policy assessment,
  not evidence of a weak actual password. Credential-capture and relay exposure
  must remain separate from password-policy results.
- **MFA:** Entra join, PRT, Windows Hello or an installed authenticator does not
  prove MFA enforcement. Mark it `NOT_EVALUATED` absent authoritative IdP/policy
  evidence; never fabricate `ENFORCED`.
- **AV/EDR:** installed software is not necessarily a registered/active antivirus.
  Keep parent AV and browser extensions, updater/helper components, EDR and
  Defender-for-Endpoint identities distinct. Separate active protection, product
  version, engine version, signature freshness, source conflicts and full health.

## Software Intelligence / CVE correctness

- **Identity correctness before coverage.** Preserve vendor, product family,
  generation, edition, component, platform and applicable version distinctions.
  Never merge Visual C++ generations, Edge/WebView2, Teams/Meeting Add-in,
  CCleaner/Update Helper or similar near matches simply to raise coverage.
- Use auditable normalization/CPE discovery traces, canonical product-family
  resolution, correct CPE 2.3 escaping, documented vendor aliases and reliable
  version/edition/environment applicability. Different version rows of one
  canonical family are not competing product identities.
- Distinguish `CONFIRMED`, `POSSIBLE`, `NOT_AFFECTED`, `NOT_EVALUATED`, and
  evaluated-zero-CVE outcomes. **No known vulnerabilities found** requires a
  completed successful evaluation, not missing mappings or provider failures.
- Respect NVD/vendor/CNA source trust, source conflicts and CISA KEV evidence.
  Do not hard-code CVE IDs/results or weaken confidence, source, range or critical
  risk triggers for a better coverage number.
- Confirmed applicable CISA KEV remediation **work items are P1 across the full
  remediation plan**, not only the Executive Summary Top 5. Do not silently
  change the separate severity/risk model.
- Keep software counting units explicit: installation records, eligible
  product-version instances, completed/partial/not-evaluated instances,
  software–CVE relationships, unique CVEs and affected endpoints. Counts and
  endpoint/fleet drill-down must reconcile, including mixed detail/legacy data.
- Maintain positive/negative/stale cache provenance, expiration and deduplicated
  upstream requests. `PARTIAL` evaluation coverage is not synonymous with NVD
  provider failure. Do not label coverage percentage a confidence score.

## Report and product delivery expectations

- Primary customer report is one **self-contained, deterministic, offline HTML**
  with embedded assets and a verifiable integrity manifest; no tracking/CDNs.
- Important results (BitLocker, AV, passwords, MFA, credential posture,
  vulnerable software, KEV, actionable remediation and limitations) should be
  understandable without reading raw JSON. Do not show misleading numeric risk
  scores, duplicated product versions or ungrounded `PASS` findings.
- Preserve Unicode/UTF-8 end to end, including Estonian `õäöü`, in the online,
  offline, CSV/JSON and HTML paths where applicable.
- Collector, CSA Lab, analysis, report and installer version identifiers must
  agree. Build provenance/commit, installer SHA-256 and source version must be
  reported honestly. Avoid hard-coded version numbers in this instructions file.

## Work procedure and testing

1. Inspect the affected code, current tests and latest sprint acceptance criteria.
   Form a minimal plan for multi-module changes; avoid unrelated refactoring.
2. Add regressions that reproduce the reported bug, including realistic adverse
   and negative cases; do not rely only on happy-path synthetic data.
3. Test touched modules and adjacent contracts, then run the repository's full
   validation/packaging workflow as the environment permits. Example commands:

   ```powershell
   python -W error::ResourceWarning -m unittest discover -s tests -q
   powershell.exe -NoProfile -File .\scripts\Invoke-CollectorTests.ps1
   ```

   Check actual prerequisites and available test runners; do not claim that
   Windows/Pester integration tests passed on an environment that cannot run them.
4. Verify no warnings, data leaks, schema breaks, test fixture contamination,
   report integrity regressions, NVD key exposure or accidentally changed risk
   behavior. Check code paths after exceptions/cancellation and provider errors.
5. Use controlled same-dataset/same-version cold/warm comparisons for performance;
   do not present different endpoints/versions as an A/B benchmark.
6. Keep real customer evidence in authorized local acceptance storage only.
   Do not upload it into Git, issue attachments, published releases or CI.
7. Keep commits focused and auditable; update docs and tests together with code.

## GitHub delivery workflow (existing project agreement)

- The user has authorized GitHub delivery as the default completion step.
  After implementing and validating an agreed change, **commit and push** to
  the existing working branch unless explicitly told to use another branch or PR.
- Check GitHub Actions for the exact commit; resolve failures caused by the
  change. Do not assert `7/7 green` without verifying the runs.
- For changes shipped in CSA Lab, wait for the installer build and Actions
  artifact upload; provide the actual build/artifact link, package version,
  installer hash and signing status. Actions artifacts are **not** GitHub Release
  assets, and a `releases/latest` URL works only when that release exists.
- Public installers should be discoverable from the repository README and
  published as verifiable GitHub Release assets **when an accepted release is
  approved**. Use the exact verified CI-built installer/commit; provide
  `CSA-Lab-Setup.exe`, `SHA256SUMS.txt` and build information. Never retag or
  silently replace an existing release's binary.
- **Pushing a completed correction is not the same as declaring live acceptance.**
  If the sprint is awaiting Architect/user live acceptance, leave release/tag
  creation pending unless the user explicitly approves it.

## End-of-sprint handoff

Report at least:

- commit hash, branch, version and changed-file/component summary;
- exact behavior before/after and outstanding limitations;
- Python / Pester / CI results with executed counts, skips and warnings;
- installer artifact link, source commit, SHA-256, signature status;
- regression results and remaining live-acceptance checks;
- evidence/identity/source-trust/risk/schema compatibility declaration;
- confirmation that no raw customer evidence or secrets were committed;
- the next recommended correction/sprint, without declaring unperformed work done.

Direct user instructions for the current sprint take precedence over these
repository defaults. Do not override explicit approval or safety boundaries.
