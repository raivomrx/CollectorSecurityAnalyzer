# Sprint 5.2.1 reporting model

CSA's unified report is an endpoint-centric, self-contained presentation of
evidence-backed assessment results. The reporting layer does not rediscover
rules, rerun analysis, or infer missing evidence.

## Risk measures

The report keeps these concepts separate:

- finding severity: the severity assigned to one technical finding;
- endpoint risk: the highest confirmed risk evidence on one endpoint;
- overall security risk: the deterministic assessment-level rating;
- risk score: a numeric ranking measure from 0 to 100;
- coverage: the proportion of expected evidence or CVE-eligible products that
  was evaluated.

The numeric risk score cannot by itself create a `CRITICAL` rating. A critical
rating requires at least one of these explicit triggers:

1. a confirmed `CRITICAL` security finding;
2. a confirmed Critical CVE affecting an installed version;
3. a future policy control explicitly marked as a critical trigger.

A possible Critical CVE is not a critical trigger. Any number of systemic
`HIGH` findings remains `HIGH` unless separate explicit critical evidence is
confirmed. Their count and prevalence affect prioritization and exposure, not
the severity boundary. Incomplete coverage changes certainty and is disclosed
in the reasoning, but does not automatically lower or increase the rating.

The report labels the numeric value as a prioritization and exposure score. It
ranks cumulative exposure and remediation priority; it does not independently
determine the Overall Security Risk severity.

## CVE terminology

- Detected CVEs: unique CVE IDs with a `CONFIRMED` or `POSSIBLE` relationship.
- Confirmed CVEs: unique IDs with at least one confirmed installed-version
  applicability relationship.
- Possible CVEs: unique IDs with only possible relationships. A confirmed
  relationship dominates a possible relationship for the same CVE ID.
- Critical CVEs: Critical-severity CVEs with confirmed applicability.
- Known Exploited Vulnerabilities: confirmed CVEs present in the CISA KEV
  catalog.

`0 CVEs` with complete coverage is an evaluated clean result. `0 CVEs` with
zero or incomplete coverage is an unevaluated or incomplete result and must not
be presented as clean.

At zero coverage, the primary CVE metric displays `NOT EVALUATED` instead of a
numeric zero. Numeric detected, confirmed and possible counts remain available
as technical context but are not presented as a completed vulnerability result.

## Customer navigation

The primary path is:

```text
Assessment -> Finding -> Endpoint -> Evidence
```

Endpoint Overview links to details in the same HTML file. Findings,
remediation actions, CVE relationships, limitations and framework traceability
all identify affected endpoints. Raw normalized evidence, provider metadata,
confidence values and digests remain collapsed in Advanced Technical Evidence.

Endpoint Overview counts only `FAIL` and `WARNING` results as security
findings. PASS and INFO results remain visible as control results and do not
inflate the finding count.

## Report search

The self-contained report provides a case-insensitive full-report search over
customer-visible content. It highlights every match, reports the total, opens
collapsed ancestors for the active match and supports Previous, Next, Enter,
Shift+Enter, Escape and Clear. Clearing search restores highlights, disclosure
state and filter visibility without reloading the report.

## Framework boundary

Knowledge-layer framework identifiers are rendered as `PROVISIONAL`
traceability unless a separately audited human review has validated them. The
report does not treat technical mappings as certification or legal compliance
determinations.

## Offline and privacy boundary

The report contains inline CSS and JavaScript and has no CDN, font, analytics or
runtime network dependency. NVD and CISA links are optional references; the
report remains readable offline. Credentials, tokens and prohibited credential
material are never included.
