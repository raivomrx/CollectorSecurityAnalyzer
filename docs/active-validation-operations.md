# Active Validation Operations

Validate policy and authorization before an assessment, then create a deterministic
plan. Prefer explicit validator IDs. Profiles are also explicit selections:
`safe-read-only`, `safe-local`, `controlled-temporary`, and the separately gated
`deep-responder-validation`.

Preview the plan first and pass its `planDigest` back to `run` with
`--require-plan-digest`. A mismatch stops before validators or the audit lifecycle
start. The planner expands formal dependencies, rejects unknown, disabled,
unauthorized, policy-blocked, or risk-escalating dependencies, and applies a
stable topological order.

Audit events are append-only JSONL entries linked by `previousEntryHash` and
`entryHash`. Events include authorization/policy digests, plan IDs, validator
status, duration, and cleanup status, but no raw evidence. `verify-audit` rejects
tampering, broken links, and incomplete lifecycle logs.

PowerShell validators use process-scoped `-ExecutionPolicy Bypass` only for a
canonical script inside the trusted CSA package after its SHA-256 digest matches
the packaged allowlist. CSA never changes persistent Execution Policy. The audit
records that the harness used Bypass.

The self-hosted Responder transport is never selected by a profile alone. It
requires `--live-responder-transport` plus exact interface, listener IP, target
IP, resolution protocol, listener port, remote computer, and firewall profile.
These values are authorization-checked and included in the plan digest.

Run the flaky-test stress gate before release:

```powershell
.\scripts\Invoke-ActiveValidationStress.ps1 -Iterations 20
```

The gate requires unique iteration IDs and rejects any new
`CSA-VALIDATION-*` temporary directory left after an iteration.

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
