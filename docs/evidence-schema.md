# Evidence Schema

Sprint 5.0 wraps the existing Collector Schema 2.0 evidence in a transport
manifest with schema version `5.0`.

```text
submission.csa.zip
  manifest.json
  evidence.json
  capability-results.json
  collection-log.json
  integrity.json
  signatures/submission.sig
```

The package manifest binds assessment, session, submission, Collector build,
collection profile, device pseudonym, timestamps, privilege context, payload
digests, and package digest.

After validation, `normalize_endpoint_package()` creates an
`EndpointEvidenceRecord` with identity, OS, hardware, privilege, domain
coverage, software, updates, protection, encryption, network, policy, services,
tasks, startup, certificates, limitations, and source digests.

Reporters consume canonical endpoint and analysis models, not raw Collector
transport data.
