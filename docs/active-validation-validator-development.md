# Active Validator Development

Implement the `ActiveValidator` protocol: `describe`, `check_applicability`,
`plan`, `execute`, and `rollback`. Metadata must state risk, network impact,
system changes, required privileges/capabilities, timeouts, evidence types, safety
constraints, and existing CSA rule IDs.

Add the implementation to `active_validation/registry.json` as `DRAFT` or
`REVIEW_REQUIRED`. A technical test does not justify `ACTIVE`; review status is an
auditable human decision. Registry metadata and implementation metadata must match.

Validators receive a minimized `ValidationContext`, not the analyzer runtime. Use
typed booleans, counts, event IDs, redacted CSA object names, and marker digests.
Do not return full event text, command lines, registry exports, packet data, user
paths, or arbitrary excerpts.

Temporary objects must use `CSA-VALIDATION-<runId>`, be tracked before use, and be
removed on success, failure, exception, timeout, and cancellation. A rollback
failure must return `ROLLBACK_FAILED` and identify only the redacted object type
and CSA name.

Mock validators live outside the production registry and cover pass, fail, error,
timeout, sensitive output, and rollback failure.
