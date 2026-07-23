# Active Validation Operations

Validate policy and authorization before an assessment, then create a deterministic
plan. Prefer explicit validator IDs. Profiles are also explicit selections:
`safe-read-only`, `safe-local`, and `controlled-temporary`.

Audit events are append-only JSONL entries linked by `previousEntryHash` and
`entryHash`. Events include authorization/policy digests, plan IDs, validator
status, duration, and cleanup status, but no raw evidence. `verify-audit` rejects
tampering, broken links, and incomplete lifecycle logs.

Crash cleanup operates only on tracked allowlisted objects whose names begin with
`CSA-VALIDATION-` and exceed the configured age. It is dry-run unless `--apply` is
specified:

```powershell
python -m active_validation.cli cleanup `
  --dry-run
```

Use `--state` and `--temporary-root` to override the default cache registry and
operating-system temporary directory.

Review `ROLLBACK_FAILED` immediately. CSA reports the redacted object type and name
and never removes unrelated host objects.
