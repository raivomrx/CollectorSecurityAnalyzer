# CSA 5.6.6.1 · Teams applicability follow-up

**Release: HOLD pending broader security remediations and live HOME/LAB retesting.**

Replayed the same 31 public NVD family-query records for Microsoft Teams
`1.4.00.32771` on Windows. The installed software identity and version, NVD
records and CVE criteria were identical across the replay. The suite also
generates a synthetic HTML report from an accepted evidence package.

| CVE | 5.6.6 | 5.6.6.1 |
| --- | --- | --- |
| [CVE-2023-29328](https://nvd.nist.gov/vuln/detail/CVE-2023-29328) | `NOT_EVALUATED` / `PLATFORM_UNKNOWN` | `AFFECTED` / `VERSION_MATCH` |
| [CVE-2023-29330](https://nvd.nist.gov/vuln/detail/CVE-2023-29330) | `NOT_EVALUATED` / `PLATFORM_UNKNOWN` | `AFFECTED` / `VERSION_MATCH` |
| [CVE-2023-24881](https://nvd.nist.gov/vuln/detail/CVE-2023-24881) | `AFFECTED` / `VERSION_MATCH` | `AFFECTED` / `VERSION_MATCH` |
| [CVE-2020-10146](https://nvd.nist.gov/vuln/detail/CVE-2020-10146) | `NOT_EVALUATED` / `VERSION_SCHEME_UNSUPPORTED` | `NOT_EVALUATED` / `VERSION_SCHEME_UNSUPPORTED` |

The first two NVD desktop criteria use `target_sw=-` and an exclusive upper
bound of `1.6.00.18681`. Each NVD record carries Microsoft's named Desktop
range with the same upper bound and an inclusive lower bound of `1.0.0`.
Microsoft identifies `1.6.00.18681` as a classic Teams Windows release.
[Microsoft's CNA records for CVE-2023-29328](https://github.com/CVEProject/cvelistV5/blob/main/cves/2023/29xxx/CVE-2023-29328.json)
and [CVE-2023-29330](https://github.com/CVEProject/cvelistV5/blob/main/cves/2023/29xxx/CVE-2023-29330.json)
· [Microsoft Teams version history](https://learn.microsoft.com/en-us/officeupdates/teams-app-versioning)

The correction uses the publisher range already delivered with the NVD
record and requires an accepted CPE identity, the exact Teams product title
and publisher, an observed Windows OS, the classic client version format
and one unambiguous Microsoft desktop range with the same exclusive upper
bound. It enforces the publisher's lower bound. A record with absent,
ambiguous or conflicting publisher range data follows the ordinary
platform checks. Other CPE environment requirements still apply.

The full replay retains a partial product evaluation while the confirmed
count rises from one to three. The regression checks that a separate
unresolved CVE leaves the assessment partial and both affected Desktop
findings stay visible in HTML. The fixture includes public vulnerability
metadata and synthetic endpoint evidence.

## Version diagnostics reviewed

| Product or group | Reason and disposition |
| --- | --- |
| Classic Teams | NVD uses the date `2020-10-29` for CVE-2020-10146. The installed build and the date cannot be ordered without a source-backed mapping. |
| IrfanView, VLC and Wireshark | The installed values are numeric. Some historical NVD entries use suffixes such as `1.98a`, `0.8.4a` or `0.99.6a`. Their ordering remains unresolved. |
| LibreOffice and Adobe Illustrator | Historical criteria include the malformed LibreOffice version `3.5.` with update `rc1`, or Illustrator names such as `cs` and `cs3`. These need source-specific interpretation. |
| Microsoft Edge | The NVD record for CVE-2023-21720 uses `109.0.15.18.78`. This does not fit the supported four-component comparison. |
| NVIDIA GeForce Experience | Some NVD bounds explicitly use `-` for version. The correction reports `CPE_VERSION_NA` instead of `VERSION_SCHEME_UNSUPPORTED`. The result remains unresolved. |
| XAMPP and Python installer components | `8.2.12-0` includes a distribution suffix with no verified ordering here. Python child components and Launcher lack the established release-title corroboration needed for the parent CPython MSI conversion. |

Re-run CVE analysis with refreshed provider data if the older NVD cache
entry lacks the publisher's affected data. A saved HTML report reflects the
analysis that generated it.
