# Assessment Console

The Console runs on the assessor's Windows 11 laboratory computer.

## Lifecycle

```powershell
python -m csa_console.cli assessment create --name "Assessment" --customer-reference CLIENT-A
python -m csa_console.cli session open --assessment CSA-... --listen-address 192.0.2.10 --allowed-source-network 192.0.2.0/24
python -m csa_console.cli collector-package create --assessment CSA-... --session SES-... --output .\collector-packages\CSA
python -m csa_console.cli server start --assessment CSA-... --session SES-...
python -m csa_console.cli assessment status --assessment CSA-...
python -m csa_console.cli analyze fleet --assessment CSA-...
python -m csa_console.cli report generate-all --assessment CSA-...
python -m csa_console.cli session close --assessment CSA-... --session SES-...
python -m csa_console.cli assessment close --assessment CSA-...
```

The server binds only the session's concrete `listenAddress`. Wildcard bind
requires an explicit code-level opt-in and is rejected by default. The Console
does not create firewall rules.

Storage is assessment-scoped under `assessments/<assessment-id>`. Writes are
atomic where state is updated, path components are allowlisted, and each state
transition is appended to the assessment audit chain.
