# CSA 5.6.7 · Report clarity

**Release HOLD. Architect review and live acceptance remain pending.**

The user's direct instruction makes detected BitLocker ON the primary card
number. The two-endpoint synthetic report therefore shows **1 / 2 reported ON**
and separately **0 confirmed protected / 2 unresolved**, followed by the existing
Shell ON/OFF indications. This is an intentional presentation change from the
brief's primary confirmed-only counter. A manual comparison outside the submitted
evidence is not converted to an authoritative Collector observation.

| Requirement | Result and regression |
| --- | --- |
| RC-1 | A shared presentation adapter uses the assessed state, authoritative protection and Shell observation. Unknown, transition and provider-conflict states remain unresolved. Shell 0 has a read-only verification recommendation. Verified decrypted and suspended states retain their distinct actions. Existing provider failures, source timestamps, raw values and conversion evidence remain available. |
| RC-2 | Each grouped finding has per-endpoint observed status and evidence, confidence, action, verification and framework links. Remediation items link back to their contributing findings. Large CVE lists are expandable and verification summaries include at most three CVE IDs. The full remediation plan retains confirmed KEV at P1. |
| RC-3 | The synthetic report reconciles 206 fleet-unique confirmed CVEs, 231 product-version/CVE relationships, 20 vulnerable product identities, 35 findings and 30 remediation items. There are 219 source rows and 156 grouped overview entries. The independent core passive coverage is 71.7%. Eligible CVE completeness is 29/200, or 14.5%, with 42 partial, 129 not evaluated, 19 ineligible and zero provider failures. All-software incomplete is 190/219. Lifecycle has zero completed assessments and is visibly NOT EVALUATED. |
| RC-4 | The fixture includes filtered administrator tokens with non-elevated Collector processes, local minimum password length zero and Windows Hello context with MFA NOT EVALUATED. Policy configuration and passive capture/relay prerequisites are explained beside the results. |
| RC-5 | The new fixture checks UTF-8, escaped injected markup, local navigation targets and unique IDs. Rendering is exercised at 1, 2, 10, 50 and 100 endpoints. An independent sidecar digest is checked against saved HTML bytes and a byte modification fails comparison. Browser visual inspection was blocked by the computer-use URL verification gate. Generated offline HTML is provided for Architect visual review. |

The fixture contains synthetic endpoints and fabricated CVEs. Public CI artifacts
contain no live HOME/LAB evidence. Provider outcome fixtures exercise rendering
without calling external CVE services or changing applicability logic. Existing
regressions cover BitLocker conversion, provider conflicts, identity,
frameworks, software matching, KEV and independent risk triggers.

Generate the comparison artifact with
`python scripts/Generate-ReportClarity.py --output test-artifacts/CSA-5.6.7-Report-Clarity.html`.
The workflow uploads HTML, model JSON and the independent integrity sidecar.
The integrity digest verifies saved report bytes when checked against that
separate trusted sidecar.

Collector engine semantics, privacy, evidence schemas, CVE source trust and
assessment risk rules retain their existing boundaries. The public release
requires the outstanding acceptance and trust gates. Sprint 5.6.8 is queued.
ADR 565 protocol-development approval was received from the project lead in
this chat on 2026-11-05. Publisher identity and enrollment provisioning remain
decisions for that sprint.
