# Collector Security

The Collector is a run-once process: verify, collect, submit or export, clean
up, and exit. It is not an agent.

## Endpoint Guarantees

- No `RunAs`, UAC prompt, privilege escalation, service, or scheduled task.
- No endpoint registry or firewall modification.
- No Active Validation, relay, poisoning, cracking, or credential capture.
- No `Win32_Product`.
- No browser history, cookies, passwords, tokens, private keys, recovery keys,
  LSASS, SAM, SECURITY, or user document content.
- Temporary data uses `%TEMP%\CSA\<submission-id>` with restricted ACLs.
- Cleanup touches only the unique CSA submission directory.

The package entrypoint refuses elevated administrator and SYSTEM tokens in
standard mode. It requires medium integrity. Membership in Local Administrators
is recorded separately from elevation.

## Trusted Script Execution

`Invoke-CSACollector.ps1` validates `trusted-manifest.json`, rejects absolute or
escaping paths, hashes every declared file, and rejects undeclared files before
loading the session configuration or invoking the Collector.

`ExecutionPolicy Bypass` applies only to this verified package invocation. The
machine or user execution policy is never changed.

## Transport

Only HTTPS is accepted. The package pins the exact session certificate SHA-256
fingerprint and has no HTTP fallback. The temporary session certificate is not
installed in an endpoint trust store.
