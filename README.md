# Collector Security Analyzer

Collector Security Analyzer (CSA) is an evidence-first Windows endpoint
assessment toolkit. CSA Lab turns the secure collection, analysis, fleet
aggregation, and reporting pipeline into one assessor-facing Windows
application.

## Normal Assessment Flow

1. Install `CSA-Lab-Setup.exe`.
2. Open **CSA Lab** from the Start menu.
3. Select **New Assessment**.
4. Enter the assessment name and expected endpoint count.
5. Confirm the collection network and select **Start Collection**.
6. Open the displayed Collector page on each Windows endpoint.
7. Download and run `CSA-Collector.exe` as the current standard user.
8. Wait until each endpoint appears as **Complete**.
9. Select **Generate Assessment Report**.
10. Open the single self-contained HTML report and stop collection.

The endpoint user does not install Python, unpack a ZIP, enter a token, change
PowerShell policy, or run a command. CSA Collector does not require
administrator rights, request UAC, install an agent, modify the endpoint
firewall or registry, or run Active Validation.

## Security Boundaries

The simpler workflow preserves the existing security controls:

- HTTPS evidence submission with exact certificate pinning;
- assessment and session binding;
- short-lived enrollment credentials;
- one-use nonce and replay protection;
- package, profile, and collector build digests;
- canonical schema and strict privacy validation;
- signed receipt and tamper-evident audit chain;
- authenticated encrypted offline fallback;
- coverage-aware evaluation and latest-device fleet deduplication;
- localhost-only administration and source-scoped remote collection access.

The generated download certificate can cause a browser warning. The endpoint
must verify that the displayed address belongs to the CSA Lab computer.
Collector TLS validation remains pinned and has no silent bypass.

## Reports

The primary customer output is one file:

```text
<Assessment-Name>-CSA-Assessment-Report.html
```

It contains the executive summary, fleet dashboard, findings, remediation,
endpoint details, evidence, framework mappings, methodology, and audit
integrity information. CSS and JavaScript are embedded, so the report opens
offline and can be archived or printed to PDF.

## Documentation

- [Paigaldamine](docs/installation-et.md)
- [Kiirjuhend](docs/quick-start-et.md)
- [Kahe arvuti hindamine](docs/two-computer-assessment-et.md)
- [Offline-hindamine](docs/offline-assessment-et.md)
- [Unified raport](docs/unified-report-et.md)
- [Tõrkeotsing](docs/troubleshooting-et.md)
- [TLS ja sertifikaadid](docs/tls-and-certificates-et.md)
- [Sprint 5.2 live acceptance](docs/sprint-5.2-acceptance.md)
- [Security model](docs/security-model.md)
- [Architecture](docs/architecture.md)

## Advanced and Developer CLI

The existing CLI remains supported for automation, CI, diagnostics, and
backward compatibility. It uses the same domain and service layers as CSA Lab:

```powershell
python -m pip install -r requirements.txt
python -m csa_console.cli --help
python -m csa_console.cli report unified --assessment CSA-...
```

Developer builds additionally use `requirements-build.txt`,
`scripts/Build-CSACollector.ps1`, and `scripts/Build-CSALab.ps1`.

## Release Trust

The build is Authenticode-ready and emits SHA-256 digests. CI can sign the Lab,
Collector, and installer when signing secrets are configured. Until a trusted
production code-signing certificate is configured, Windows SmartScreen may
warn about locally built or CI-produced executables.
