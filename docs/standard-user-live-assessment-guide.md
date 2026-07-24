# Standard-User Live Assessment Guide

This guide covers one Windows 11 laboratory computer and 13 Windows 11
endpoints.

## 1. Laboratory Preparation

1. Use an encrypted lab volume and install Python 3.12 dependencies.
2. Select one concrete lab interface IP. Do not use `0.0.0.0` or `::`.
3. Confirm the 13 endpoint source addresses are inside an assessment-only
   network range.
4. Do not create an endpoint or Console firewall rule implicitly. If the lab
   requires one, create a separately authorized, source-scoped rule and record
   its cleanup outside the standard workflow.

```powershell
python -m pip install -r requirements.txt
```

## 2. Create Assessment and Session

```powershell
python -m csa_console.cli assessment create `
  --name "Client Windows 11 endpoint assessment" `
  --customer-reference CLIENT-A `
  --assessment-id CSA-2026-001

python -m csa_console.cli session open `
  --assessment CSA-2026-001 `
  --expected-devices 13 `
  --allowed-submissions 20 `
  --listen-address 192.0.2.10 `
  --port 8443 `
  --allowed-source-network 192.0.2.0/24
```

Expected: session `OPEN`, collector mode
`STANDARD_USER_COLLECTION`, expiration, TLS fingerprint, and a one-time-visible
enrollment token.

## 3. Create and Verify Collector Package

```powershell
$env:CSA_ENROLLMENT_TOKEN = Read-Host "Enrollment token"
python -m csa_console.cli collector-package create `
  --assessment CSA-2026-001 `
  --session SES-... `
  --server-url https://192.0.2.10:8443 `
  --output .\collector-packages\CSA-2026-001
Remove-Item Env:\CSA_ENROLLMENT_TOKEN

python -m csa_console.cli collector-package verify `
  --path .\collector-packages\CSA-2026-001
```

Expected: all file digests valid, HTTPS URL and session fingerprint present,
no server private key, operator credential, or Active Validation authorization.

## 4. Start Console

```powershell
python -m csa_console.cli server start `
  --assessment CSA-2026-001 `
  --session SES-...
```

Expected: concrete listen IP, TLS port and fingerprint, allowed source range,
profile `windows-standard-v1`, endpoint administrator requirement `NO`, Active
Validation `DISABLED`.

## 5. Run Each Endpoint

Sign in with a user that is not a Local Administrators group member. Open a
normal PowerShell window. Do not use "Run as administrator".

```powershell
whoami /groups
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-CSACollector.ps1
```

Expected:

```text
Collector mode: STANDARD USER
Administrator rights required: NO
Active security testing: NO
Collection completed
Submission accepted
Receipt ID: ...
Local temporary data removed: YES
```

No UAC dialog may appear. Confirm `%TEMP%\CSA` has no new retained submission
directory.

## 6. Verify Fleet Receipt

```powershell
python -m csa_console.cli assessment status --assessment CSA-2026-001
python -m csa_console.cli submission list --assessment CSA-2026-001
```

Expected after all endpoints: 13 unique accepted submission IDs, no duplicate,
13 endpoint findings files, and 13 endpoint reports.

## 7. Negative Tests

Duplicate: resend an already consumed package. Expected
`REJECTED_REPLAY`.

Expired token: close or expire the session, then request a nonce. Expected
`REJECTED_EXPIRED` or `REJECTED_TOKEN`.

Wrong TLS fingerprint: modify a disposable test package fingerprint and run.
Expected `SERVER_IDENTITY_VALIDATION_FAILED`; no HTTP fallback.

Source mismatch: run from outside `allowedSourceNetworks`. Expected
`REJECTED_UNAUTHORIZED_SOURCE`.

Tamper: alter one archive byte. Expected digest or archive-safety rejection and
no accepted evidence.

## 8. Offline Test

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-CSACollector.ps1 `
  -NoSubmit `
  -ExportPath E:\CSA-Drop

python -m csa_console.cli submission import `
  --assessment CSA-2026-001 `
  --file E:\CSA-Drop\SUB-....csa
```

Expected: encrypted file, successful import and analysis. Reimport must return
duplicate/replay. A tampered envelope or wrong session key must fail.

## 9. Analyze and Report

```powershell
python -m csa_console.cli analyze fleet --assessment CSA-2026-001
python -m csa_console.cli report generate-all --assessment CSA-2026-001
```

Check:

- endpoint count 13;
- domain coverage and privilege limitations visible;
- repeated findings deduplicated at fleet level;
- endpoint, fleet, executive and dashboard HTML present;
- no external CDN references;
- Active Validation shown as not performed.

## 10. Close, Export, and Verify

```powershell
python -m csa_console.cli session close --assessment CSA-2026-001 --session SES-...
python -m csa_console.cli assessment close --assessment CSA-2026-001
python -m csa_console.cli assessment export --assessment CSA-2026-001 --output .\CSA-2026-001.csa --encrypt
python -m csa_console.cli assessment verify --file .\CSA-2026-001.csa
```

Expected: archive verification `VERIFIED`, final archived audit hash present,
and no endpoint temp files or Console sockets remain.

## Acceptance Record

Retain the self-hosted workflow artifact from
`.github/workflows/standard-user-live.yml`. A run under an
`ADMIN_MEMBER_NOT_ELEVATED` token is useful compatibility evidence but is not
the true non-admin production acceptance.
