# Standard-User Collection

`STANDARD_USER_COLLECTION` is the default and acceptance target.

The process must be:

- non-elevated;
- medium integrity;
- either a true standard user or an administrator-group member with a filtered
  non-elevated token.

Reports distinguish those two cases. Only a true standard-user account satisfies
the production non-admin acceptance gate.

The default privacy policy omits hostnames, IP and MAC addresses, local admin
names, browser extensions, and certificate subjects. User and tenant identifiers
are hashed. Software inventory remains enabled.

Typical invocation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-CSACollector.ps1
```

Offline invocation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-CSACollector.ps1 `
  -NoSubmit `
  -ExportPath E:\CSA-Drop
```

The offline `.csa` envelope is encrypted before it leaves the temporary
directory.
