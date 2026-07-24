# Collector Security Analyzer

CSA is an evidence-first Windows endpoint assessment toolkit. The Sprint 5.0
Assessment Console adds session-bound standard-user collection, secure HTTPS
submission, canonical evidence normalization, fleet analysis, and endpoint,
technical, and executive HTML reports.

## Quick Start

```powershell
python -m pip install -r requirements.txt

python -m csa_console.cli assessment create `
  --name "Client Windows endpoint assessment" `
  --customer-reference CLIENT-A

python -m csa_console.cli session open `
  --assessment CSA-2026-001 `
  --expected-devices 13 `
  --listen-address 192.0.2.10 `
  --allowed-source-network 192.0.2.0/24
```

The enrollment token is displayed once and stored by the Console only as a
SHA-256 verifier. Set it temporarily in `CSA_ENROLLMENT_TOKEN`, create the
Collector package, and then remove it from the environment:

```powershell
$env:CSA_ENROLLMENT_TOKEN = Read-Host "Enrollment token"
python -m csa_console.cli collector-package create `
  --assessment CSA-2026-001 `
  --session SES-... `
  --output .\collector-packages\CSA-2026-001
Remove-Item Env:\CSA_ENROLLMENT_TOKEN

python -m csa_console.cli server start `
  --assessment CSA-2026-001 `
  --session SES-...
```

On an endpoint, run the generated package from a normal, non-elevated
PowerShell process:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-CSACollector.ps1
```

This one-shot flow does not request elevation, install an agent, change the
registry or firewall, or run Active Validation.

See [standard-user collection](docs/standard-user-collection.md),
[Console operations](docs/assessment-console.md), and the
[live assessment guide](docs/standard-user-live-assessment-guide.md).
