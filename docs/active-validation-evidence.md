# Active Validation Evidence

Active evidence is separate from passive collector evidence. It contains only the
validator ID/version, run ID, status, timestamps, duration, host identifier hash,
authorization and policy digests, typed observations, limitations, and cleanup
state.

Allowed evidence includes booleans, bounded counts, event IDs, timestamps,
redacted CSA object names, policy-state enums, provenance labels, and marker
digests. The Script Block Logging validator stores the marker digest and whether
Event ID 4104 was found, never the event message or script block text.

Raw event XML, full command lines, user-profile paths, registry exports, packet
captures, authentication material, passwords, tokens, private keys, and arbitrary
log excerpts are not allowed. The recursive guard scans evidence, limitations,
error summaries, and remaining cleanup object names. A match replaces validator
output with `SENSITIVE_EVIDENCE_BLOCKED`; the matched value is never logged.

`ActiveValidationResult` is serialized only after rollback. Any incomplete cleanup
sets `manualCleanupRequired` and changes the result to `ROLLBACK_FAILED`. Audit
JSONL records lifecycle metadata but never embeds active evidence.
