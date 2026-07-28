# Sprint 5.1 Acceptance Status

Automated tests cover the localhost UI boundary, scoped HTTPS portal,
certificate pinning, portal expiry and download limits, CSRF, Collector overlay
integrity, firewall specification, crash recovery, one-endpoint unified report,
and a 13-endpoint synthetic submission-analysis-report flow.

The GitHub hosted Windows smoke test is not a substitute for the mandatory
two-computer true non-admin acceptance test.

Sprint 5.1 must not be marked fully complete until a real Windows 11 endpoint
that is not a member of Local Administrators downloads and runs the Collector
from a second computer without UAC and produces an accepted HTTPS submission.

Production code signing also remains incomplete until a trusted Authenticode
certificate is configured.
