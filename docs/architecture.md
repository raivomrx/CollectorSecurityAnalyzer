# CSA Lab Architecture

## Component Flow

```text
CSA-Lab.exe
  -> localhost admin UI (127.0.0.1, random port, CSRF)
  -> LabApplicationService
       -> assessment/session services
       -> Collector package builder
       -> firewall adapter
       -> scoped HTTPS portal and submission listener
       -> normalization and analysis pipeline
       -> fleet analyzer
       -> unified report generator
       -> audit and recovery

CSA-Collector.exe
  -> stable .NET bootstrap
  -> verified assessment-bound package
  -> standard-user Windows collection
  -> pinned HTTPS or encrypted offline package
```

The GUI and CLI call the same domain/application services. The GUI does not
reimplement token verification, package validation, evidence analysis, fleet
deduplication, or reporting logic.

## Storage Decision

Sprint 5.1 keeps the existing file-based storage model. This avoids a
high-risk migration while raw, canonical, normalized, findings, receipts,
reports, and audit data are already assessment-scoped.

Hardening added for the GUI runtime:

- canonical and atomic JSON writes with unique temporary files;
- process-wide per-path locks;
- isolated assessment directories;
- deterministic indexes and latest-device selection;
- replay and duplicate controls;
- crash recovery state without automatic evidence deletion.

The application is single-instance by operational design. A future multi-user
or service-hosted product should add cross-process locks or a transactional
metadata database without moving immutable evidence into an opaque database.

## Packaging Decision

CSA Lab uses a PyInstaller one-folder distribution wrapped by NSIS.
This preserves the audited Python services, bundles the runtime, supports a
single installer and uninstaller, and avoids a second business-logic
implementation. One-folder mode reduces one-file self-extraction behavior and
is generally easier to inspect and less prone to antivirus false positives.

CSA Collector uses a small .NET Framework executable. Windows 11 includes the
required runtime, the binary is straightforward to inspect and Authenticode
sign, and it does not bundle Python. The session payload is assessment-bound
because the primary user flow has no arguments, token entry, sidecar, or custom
protocol.

Trade-offs:

- PyInstaller Lab artifacts are larger than a native .NET rewrite;
- unsigned development binaries may trigger SmartScreen;
- assessment-bound Collector artifacts cannot be pre-signed individually
  unless a controlled signing service is introduced;
- the stable bootstrap can be signed, while its payload integrity and
  server-side build trust remain independently verified.

Production releases require a documented Authenticode certificate and signing
service strategy. CI already supports optional signing secrets.

## Lifecycle

Creating an assessment opens a bounded session and prepares the Collector but
does not expose a network listener. Starting collection creates the exact
firewall rule, activates the portal, and starts TLS. Pause removes network
access and pauses the credential. Stop closes the session. Application shutdown
pauses active sessions and removes runtime access. Unexpected termination is
detected on the next start and offered as Resume or Close and Clean Up.

## Future CSA Home

CSA Home can reuse collection capabilities, evidence schemas, normalization,
rules, knowledge, compliance, fleet, and unified reporting. It should replace
the remote portal workflow with a local report viewer or localhost/file output
and must not normally present a browser certificate warning.
