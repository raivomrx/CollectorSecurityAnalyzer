# CSA Architecture

CSA separates collection, trust validation, evaluation, and presentation:

```text
Windows 11 endpoint (medium integrity)
  -> one-shot standard-user Collector
  -> canonical, session-bound evidence package
  -> pinned HTTPS or encrypted offline envelope
  -> Assessment Console quarantine and validation
  -> canonical EndpointEvidenceRecord
  -> existing Rule, Knowledge, CVE and Compliance engines
  -> endpoint findings
  -> deterministic fleet aggregation
  -> endpoint, fleet, executive and dashboard HTML
```

## Trust Boundaries

The endpoint never exposes an inbound management service. The Console never
sends commands to endpoints. A session is `OPEN`, unexpired, source-scoped,
submission-limited, and bound to a collection profile and trusted Collector
build digest before it can accept evidence.

Submission validation is ordered:

```text
RECEIVED -> QUARANTINED -> TRANSPORT_VALIDATED
-> INTEGRITY_VALIDATED -> SCHEMA_VALIDATED -> PRIVACY_SCANNED
-> EVIDENCE_ACCEPTED -> ANALYZED -> REPORTED
```

Rejected archives are removed from quarantine by default. Audit records contain
only identifiers, states, and digests.

## Separation From Active Validation

Sprint 4.1 Active Validation remains a separate command, policy, authorization,
and worker boundary. The standard profile cannot include it, the package config
sets it to false, and the endpoint runner rejects a config that enables it.

## Determinism

Canonical JSON, sorted identifiers, stable fleet grouping, fixed ZIP member
ordering, and report data models make semantic outputs repeatable. Render-time
metadata is kept in integrity sidecars instead of changing the report model.
