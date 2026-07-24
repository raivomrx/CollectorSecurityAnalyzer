# Reporting

The Console produces:

- endpoint technical reports;
- fleet technical report;
- plain-language executive report;
- local read-only fleet dashboard.

All use Jinja2 autoescaping and local CSS. There are no external CDNs,
telemetry calls, remote fonts, or scripts.

Endpoint reports display collection mode, administrative rights used, Active
Validation state, coverage by domain, findings, inventory, limitations, and
integrity references.

Fleet reports deduplicate systemic findings and link them to endpoint
pseudonyms. Executive reports summarize posture, significant systemic risks,
positive results, and prioritized remediation without copying raw technical
evidence.

Each semantic report model includes assessment ID, evidence-set digest, audit
hash at generation, engine version, and framework digest placeholder. File and
model digests are written to a local integrity sidecar.
