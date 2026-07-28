# CSA Lab Security Model

## Trust Boundaries

CSA Lab has three explicit adapters around shared domain services:

1. a localhost-only administration server with a per-process CSRF token;
2. a remote, source-scoped TLS listener exposing only join, download, nonce,
   submission, and receipt behavior;
3. a one-shot standard-user Collector.

The remote listener has no route to assessment lists, endpoint dashboards,
reports, audit data, settings, or lifecycle controls. Access logs omit join
codes and authorization material.

## Collector Binding

Sprint 5.1 uses an assessment-bound Collector because a stable executable
cannot reliably learn the browser download origin without an argument, sidecar,
custom protocol, or mutable payload.

The implementation separates:

- a stable, Authenticode-ready .NET Framework bootstrap executable;
- a deterministic ZIP overlay containing the existing session package;
- a trailer with payload length, SHA-256 digest, and format marker;
- the trusted package manifest with exact path, size, and file digests;
- server-side trust for the package's collector build digest.

The bootstrap extracts into a unique current-user-and-SYSTEM ACL directory,
validates every declared file, rejects path traversal, invokes the existing
standard-user PowerShell runner, and removes the temporary directory. The
runner rejects elevated/SYSTEM or non-medium-integrity execution.

An attacker who rewrites the executable and manifest still cannot submit under
an untrusted collector build digest. Production distribution additionally
requires Authenticode signing.

## Submission Controls

Online submission retains:

- TLS 1.2 or newer;
- exact server certificate fingerprint pinning;
- short-lived assessment/session credential;
- source network scope;
- one-use nonce;
- replay and duplicate rejection;
- canonical package digest and HMAC binding;
- collection profile digest;
- trusted collector build digest;
- schema and privacy validation;
- signed server receipt;
- tamper-evident assessment audit chain.

Offline submission uses an assessment public key, authenticated encryption,
associated assessment/session/submission data, expiry, digest binding, and the
same downstream validation pipeline.

## Local Data

Per-user application and assessment data lives under `%LOCALAPPDATA%\CSA`.
Assessment directories are restricted to the current Windows identity and
Local System. State writes use canonical JSON, unique temporary files, atomic
replace, and process-wide path locks. The application runs one in-process
listener per active assessment and detects orphaned state on restart.

## Firewall

CSA requests elevation only on the Lab computer. A rule is rejected unless it
has the CSA temporary namespace and a concrete executable, TCP port, local IP,
source subnet, and Private/Domain profile. Stop, pause, controlled shutdown, and
recovery remove the exact rule.

## Privacy

The endpoint collector and server reject credential-like fields and forbidden
sensitive material before analysis. Reports are rendered from accepted,
normalized evidence. Audit records contain lifecycle metadata, digests, IDs,
and safe error categories, not raw evidence or credentials.

Active Validation remains isolated and disabled in the standard-user flow.
