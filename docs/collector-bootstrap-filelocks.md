# Collector bootstrap integrity and Enterprise PowerShell transport

The EXE remains the recommended Collector and the Home/public distribution
transport. CSA Lab's session Join page also offers **PowerShell Collector —
Enterprise compatibility**, downloaded as `CSA-PowerShell-Collector.zip`.

Both downloads contain the same generated package bytes: the same Collector
scripts, trusted manifest, session binding, enrollment token, TLS certificate
identity, collection profile, privacy policy, and evidence schema. Submission
uses the existing nonce, enrollment, trusted-build and receipt validation. Both
downloads share portal authorization, source scope, expiry, throttling and the
download budget. No alternative collection implementation or submission API is
introduced. Existing assessments can expose their original verified package
when collection is restarted; a newly created assessment is needed to obtain
the updated bootstrapper and scripts.

For the PowerShell transport, extract **all** ZIP entries into a new folder and
open a **non-elevated** PowerShell window there:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CSACollector.ps1
```

The execution policy applies only to that process; organization policy still
applies. No `IEX(DownloadString())`, persistent execution-policy change, endpoint
protection exclusion, or endpoint protection disabling is required.

The bootstrapper verifies the appended archive digest before extraction, reads
the manifest from the archive, validates the entire declared inventory and
Windows paths before creating files, then hashes the entry bytes as they are
written. Each declared digest and size must match. Newly extracted modules are
not reopened for bootstrap integrity hashing. The manifest itself is covered by
the existing archive digest. This retains the existing package trust model;
it does not introduce a new digital signature scheme.

Necessary bootstrap file opens and the shared PowerShell package hashing use
bounded backoff only for Windows `ERROR_SHARING_VIOLATION` (32) and
`ERROR_LOCK_VIOLATION` (33). The eight delays are 250, 500, 1000, and five 2000 ms
waits (11.75 seconds total, plus operation time). No digest mismatch, malformed
manifest, unsafe path, missing file, access-denied error, or other trust failure
is retried. The PowerShell transport independently verifies every trusted file
before collection, including when started by the EXE.

Progress reports `TRANSIENT_FILE_LOCK` and explains that endpoint security may
be scanning a Collector file. If the lock persists, the diagnostic is
`CSA-COL-FILELOCK` / `TRANSIENT_FILE_LOCK`; verification fails. A lock never
counts as a successful integrity check. The user can retry shortly while
keeping endpoint protection enabled.

Windows regression:

```powershell
python -W error::ResourceWarning -m unittest tests.test_collector_bootstrap -v
```

The test compiles a harness against the production bootstrapper methods. A
separate process holds an exclusive Windows handle on a Collector `.psm1` for
three seconds. An extraction regression finishes integrity verification while
a newly extracted module remains locked by that process, proving the bootstrap
does not reopen it. Both the bootstrap file retry and shared PowerShell hashing
recover; persistent locks fail closed in both. Archive entry tampering with a
recomputed outer digest, size errors, duplicate declarations, malformed
manifests, unsafe paths, missing/undeclared files and non-lock I/O errors fail
without backoff. The HTTPS portal regression compares the entire downloaded
ZIP with the EXE's appended archive. These are Windows integration checks,
not a claim that the two customer endpoints have passed a new live acceptance.

Local validation completed on 2026-10-07: **513 Python tests and 86 PowerShell
tests passed**. The CSA Lab installer build also passed. The local build is
unsigned because local signing credentials are unavailable. The GitHub Actions
Collector build includes the Windows file-lock regression as a required step.
