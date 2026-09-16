# Sprint 5.4 public-source regressions

Retrieved 2026-09-15 from the public NVD API and CVE Program repository.
These files contain public vulnerability/catalog data, not HOME evidence.

`audacity-cpes.json` was added on 2026-09-16 from the same public CPE endpoint
with `keywordSearch=Audacity`. It includes the deprecated `audacity:audacity`
identity and active `audacityteam:audacity` version rows. A live query for the
active 2.4.2 CPE returned zero vulnerability records, independently verifying the
completed clean-state control.

* CPE candidates: `https://services.nvd.nist.gov/rest/json/cpes/2.0` with
  `keywordSearch=Adobe Lightroom Classic`, `Adobe Premiere Pro`, and `LibreOffice`.
  Representative rows retain original NVD fields, including edition, deprecation
  and competing Premiere CS identities. Fixtures are bounded samples; production
  discovery queries the provider and evaluates its complete returned candidate set.
* NVD records: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-40776`
  and `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9653`.
* CNA records: `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/40xxx/CVE-2021-40776.json`
  and `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2020/9xxx/CVE-2020-9653.json`.

The Lightroom test runs inventory normalization, remote candidate selection,
NVD version/environment applicability and CNA source-trust resolution. Edition
and OS negative cases preserve the same constraints. No CVE ID is hardcoded into
production selection or applicability. The two vendor advisories are Adobe
[APSB21-97](https://helpx.adobe.com/security/products/lightroom/apsb21-97.html) and
[APSB20-38](https://helpx.adobe.com/security/products/premiere_pro/apsb20-38.html).
