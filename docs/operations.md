# Console Operations

## Storage and Retention

Assessment data can include sensitive configuration. Keep `assessments/` on an
encrypted laboratory volume with assessor-only ACLs. Do not commit it.

Export with a passphrase entered through a secure prompt:

```powershell
python -m csa_console.cli assessment export `
  --assessment CSA-2026-001 `
  --output .\CSA-2026-001.csa `
  --encrypt
```

Verify later:

```powershell
python -m csa_console.cli assessment verify --file .\CSA-2026-001.csa
```

The export uses scrypt and AES-256-GCM. Keys and passphrases are not accepted on
the command line or written to configuration.

## Shutdown

Stop the Console with `Ctrl+C`. The HTTPS socket closes without creating or
removing firewall rules. In-flight requests are bounded by the session timeout.
Quarantine contains only in-progress packages; rejected content is removed and
represented by safe metadata.

## Recovery

Run `assessment verify` against live storage to verify its audit hash chain.
Run archive verification before relying on a transferred assessment. A failed
verification must be treated as integrity loss, not as a warning.
