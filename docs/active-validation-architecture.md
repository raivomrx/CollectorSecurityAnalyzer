# Active Validation Architecture

Active Validation is an optional layer after passive rule evaluation. It confirms
selected runtime behavior while preserving the original `Finding`. A rule may have
three separate outcomes: passive, active, and correlated.

The engine is disabled by default. Running it requires an enabled safety policy,
a valid time-limited authorization file, and an explicit validator ID or profile.
Only registry entries with status `ACTIVE` can be planned.

```powershell
python analyzer.py input.json `
  --active-validation `
  --active-policy policy.json `
  --active-authorization authorization.json `
  --validator VAL-DEFENDER-RUNTIME-001
```

Each validator runs in a child process with a per-validator timeout, file-backed
bounded stdout/stderr, a minimal environment, and structured JSON output. The
report and `.analysis.json` sidecar include active results and passive/active
correlation. A missing or inconclusive active result never changes the passive
finding.

Administrative commands:

```powershell
python -m active_validation.cli list
python -m active_validation.cli show VAL-DEFENDER-RUNTIME-001
python -m active_validation.cli validate-policy policy.json
python -m active_validation.cli validate-authorization authorization.json
python -m active_validation.cli verify-audit output.audit.jsonl
```
